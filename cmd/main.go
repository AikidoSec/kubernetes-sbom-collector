package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"time"

	"aikidoSec.kubernetes-sbom-collector/internal/clients/agent"
	"aikidoSec.kubernetes-sbom-collector/internal/clients/output"
	"aikidoSec.kubernetes-sbom-collector/internal/controllers"
	"aikidoSec.kubernetes-sbom-collector/internal/predicates"
	"aikidoSec.kubernetes-sbom-collector/internal/service"
	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const (
	defaultNamespace = "aikido"
	defaultAgentURL  = "http://aikido-kubernetes-agent:81"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

// nolint:gocyclo
func main() {
	var probeAddr string
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.Parse()

	// Silence controller-runtime logs
	ctrl.SetLogger(logr.New(log.NullLogSink{}))

	ctx := context.Background()
	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ns, exists := os.LookupEnv("AGENT_NAMESPACE")
	if !exists {
		ns = defaultNamespace
	}

	agentAddress, exists := os.LookupEnv("AGENT_URL")
	if !exists {
		agentAddress = defaultAgentURL
	}

	env, _ := os.LookupEnv("ENVIRONMENT")

	podName, exists := os.LookupEnv("POD_NAME")
	if !exists {
		l.Error("POD_NAME environment variable not set")
		os.Exit(1)
	}

	hasSecretsPermissionStr, exists := os.LookupEnv("SECRETS_ACCESS_ENABLED")
	if !exists {
		hasSecretsPermissionStr = "false"
	}
	hasSecretsPermission, err := strconv.ParseBool(hasSecretsPermissionStr)
	if err != nil {
		l.Error("error parsing SECRETS_ACCESS_ENABLED", "error", err)
		os.Exit(1)
	}

	runAsDaemonSet := true
	runAsDaemonSetStr, exists := os.LookupEnv("RUN_COLLECTOR_AS_DAEMONSET")
	if exists {
		enabled, err := strconv.ParseBool(runAsDaemonSetStr)
		if err != nil {
			l.Error("error parsing RUN_COLLECTOR_AS_DAEMONSET. Defaulting to true", "error", err)
		} else {
			runAsDaemonSet = enabled
		}
	}

	errorLogsSuppressed := false
	errorLogsSuppressedStr, exists := os.LookupEnv("SUPPRESS_ERROR_LOGS")
	if exists {
		enabled, err := strconv.ParseBool(errorLogsSuppressedStr)
		if err != nil {
			l.Error("error parsing SUPPRESS_ERROR_LOGS. Defaulting to false", "error", err)
		} else {
			errorLogsSuppressed = enabled
		}
	}

	ctrlConfig, err := ctrlconfig.GetConfig()
	if err != nil {
		l.Error("error getting kubeconfig", "error", err)
		os.Exit(1)
	}

	clientSet, err := kubernetes.NewForConfig(ctrlConfig)
	if err != nil {
		l.Error("error getting clientSet", "error", err)
		os.Exit(1)
	}

	nodeName, err := GetNodeNameForPod(ctx, clientSet, podName, ns)
	if err != nil {
		l.Error("error getting node name for pod", "error", err)
	}

	l.Info("Starting sbom-collector operator", "node", nodeName, "namespace", ns, "pod", podName, "agent_address", agentAddress)

	agentClient, err := agent.NewClient(l, agentAddress, time.Second*30)
	if err != nil {
		l.Error("error creating agent client", "error", err)
		os.Exit(1)
	}

	// Wait 30s for the agent to be ready
	if env != "local" {
		time.Sleep(30 * time.Second)
	}

	// Get operator configuration from the agent
	operatorConfig, err := agentClient.GetCollectorConfig(ctx)
	if err != nil {
		l.Error("error getting operator config", "error", err)
		os.Exit(1)
	}
	outputClient, err := output.NewClient(l, operatorConfig.APIHost, time.Second*30)
	if err != nil {
		l.Error("error creating output client", "error", err)
		os.Exit(1)
	}

	operatorLogger := logger.NewLogger(l, agentAddress, errorLogsSuppressed)
	svc := service.NewService(operatorLogger, outputClient, agentClient)

	// Capture the start time to filter out old completed pods
	collectorStartTime := time.Now()

	// Set up the controller manager
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		// Disable metrics server
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: probeAddr,
		Cache: cache.Options{
			// Restrict cache to only Pod objects to minimize memory usage in large clusters
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Pod{}: {},
			},
			DefaultTransform: func(obj any) (any, error) {
				metaObj, err := meta.Accessor(obj)
				if err != nil {
					return obj, nil
				}

				// Remove unnecessary annotations to reduce memory footprint
				annotations := metaObj.GetAnnotations()
				if annotations != nil {
					// Remove kubectl annotations that are not needed for SBOM generation
					delete(annotations, "kubectl.kubernetes.io/last-applied-configuration")
					delete(annotations, "deployment.kubernetes.io/revision")
					delete(annotations, "kubernetes.io/change-cause")
					metaObj.SetAnnotations(annotations)
				}

				// Remove managed fields to reduce memory usage
				if metaObj.GetManagedFields() != nil {
					metaObj.SetManagedFields(nil)
				}

				// Pod-specific filtering and optimizations
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					return obj, nil
				}

				// Skip pods from excluded namespaces entirely to reduce cache size
				if slices.Contains(operatorConfig.ExcludedNamespaces, pod.Namespace) {
					return nil, nil
				}

				if runAsDaemonSet {
					// Skip pods that are not on the current node to dramatically reduce memory usage
					if nodeName != "" && pod.Spec.NodeName != nodeName {
						return nil, nil
					}
				}

				// Skip caching pods that are in Succeeded or Failed phase if they were created before the collector started.
				// This avoids processing old completed pods while still handling pods that complete during this run.
				if (pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed) &&
					pod.DeletionTimestamp.IsZero() &&
					pod.CreationTimestamp.Time.Before(collectorStartTime) {
					return nil, nil
				}

				// Skip pods in pending phase without resolved images to reduce cache size
				// We'll pick them up later when they transition to a more stable state
				if pod.Status.Phase == corev1.PodPending {
					// Check if images are resolved
					imagesResolved := true
					for _, containerStatus := range pod.Status.ContainerStatuses {
						if containerStatus.ImageID == "" {
							imagesResolved = false
							break
						}
					}
					for _, initContainerStatus := range pod.Status.InitContainerStatuses {
						if initContainerStatus.ImageID == "" {
							imagesResolved = false
							break
						}
					}
					for _, ephemeralContainerStatus := range pod.Status.EphemeralContainerStatuses {
						if ephemeralContainerStatus.ImageID == "" {
							imagesResolved = false
							break
						}
					}
					if !imagesResolved {
						return nil, nil
					}
				}

				// Remove unnecessary pod-specific fields to reduce memory
				pod.Status.QOSClass = ""
				for i := range pod.Spec.Containers {
					pod.Spec.Containers[i].Resources = corev1.ResourceRequirements{}
					pod.Spec.Containers[i].LivenessProbe = nil
					pod.Spec.Containers[i].ReadinessProbe = nil
					pod.Spec.Containers[i].StartupProbe = nil
					pod.Spec.Containers[i].Lifecycle = nil
					pod.Spec.Containers[i].SecurityContext = nil
				}

				for i := range pod.Spec.InitContainers {
					pod.Spec.InitContainers[i].Resources = corev1.ResourceRequirements{}
					pod.Spec.InitContainers[i].LivenessProbe = nil
					pod.Spec.InitContainers[i].ReadinessProbe = nil
					pod.Spec.InitContainers[i].StartupProbe = nil
					pod.Spec.InitContainers[i].Lifecycle = nil
					pod.Spec.InitContainers[i].SecurityContext = nil
				}

				return pod, nil
			},
		},
	})
	if err != nil {
		operatorLogger.ReportError(ctx, err, "error creating manager", "agentSetupError")
		os.Exit(1)
	}

	watcherOptions := controller.Options{
		CacheSyncTimeout: operatorConfig.ControllerCacheSyncTimeout,
	}
	watcherSelector := models.WatcherSelector{
		GroupVersionKind: schema.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		ExcludedNamespaces: operatorConfig.ExcludedNamespaces,
	}

	// Create and register the watcher that listens for Pod events
	if err = (&controllers.Watcher{
		KubernetesClientSet:                clientSet,
		Logger:                             operatorLogger,
		Client:                             mgr.GetClient(),
		Scheme:                             mgr.GetScheme(),
		Watched:                            watcherSelector,
		OperatorService:                    svc,
		HasSecretsPermission:               hasSecretsPermission,
		CollectorNamespace:                 operatorConfig.Namespace,
		CollectorServiceAccountName:        operatorConfig.ServiceAccountName,
		CollectorServiceAccountPullSecrets: operatorConfig.ServiceAccountPullSecrets,
	}).SetupWithManager(mgr, watcherOptions, predicates.NewPodPredicate(operatorConfig.ExcludedNamespaces, nodeName, runAsDaemonSet)); err != nil {
		operatorLogger.ReportError(ctx, err, "error creating watcher", "agentSetupError")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		operatorLogger.ReportError(ctx, err, "error adding healthz check", "agentSetupError")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		operatorLogger.ReportError(ctx, err, "error adding readyz check", "agentSetupError")
		os.Exit(1)
	}
	l.Info("SBOM collector operator started successfully", "excluded_namespaces", operatorConfig.ExcludedNamespaces)

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		operatorLogger.ReportError(ctx, err, "error starting manager", "agentSetupError")
		os.Exit(1)
	}
}

func GetNodeNameForPod(ctx context.Context, clientSet *kubernetes.Clientset, podName, podNamespace string) (string, error) {
	pod, err := clientSet.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting pod: %w", err)
	}

	return pod.Spec.NodeName, nil
}

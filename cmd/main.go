package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"aikidoSec.kubernetes-sbom-collector/internal/clients/agent"
	"aikidoSec.kubernetes-sbom-collector/internal/clients/output"
	"aikidoSec.kubernetes-sbom-collector/internal/controllers"
	"aikidoSec.kubernetes-sbom-collector/internal/predicates"
	"aikidoSec.kubernetes-sbom-collector/internal/service"
	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const (
	defaultNamespace = "aikido"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

// nolint:gocyclo
func main() {
	var probeAddr, agentAddress string
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&agentAddress, "agent-address", "", "The address the Aikido kubernetes agent is running.")
	flag.Parse()

	// Silence controller-runtime logs
	ctrl.SetLogger(logr.New(log.NullLogSink{}))

	ctx := context.Background()
	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ns, exists := os.LookupEnv("AGENT_NAMESPACE")
	if !exists {
		ns = defaultNamespace
	}

	if agentAddress == "" {
		agentAddress = "http://kubernetes-agent:81"
	}

	env, _ := os.LookupEnv("ENVIRONMENT")

	podName, exists := os.LookupEnv("POD_NAME")
	if !exists {
		l.Error("POD_NAME environment variable not set")
		os.Exit(1)
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

	operatorLogger := logger.NewLogger(l, agentAddress)
	svc := service.NewService(operatorLogger, outputClient, agentClient)

	// Set up the controller manager
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		// Disable metrics server
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: probeAddr,
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Pod{}: {},
			},
			DefaultTransform: func(obj any) (any, error) {
				obj, err := cache.TransformStripManagedFields()(obj)
				if err != nil {
					return obj, err
				}

				// Remove `kubectl.kubernetes.io/last-applied-configuration` annotation from objects
				if metaObj, ok := obj.(metav1.ObjectMetaAccessor); ok {
					annotations := metaObj.GetObjectMeta().GetAnnotations()
					if annotations != nil {
						delete(annotations, "kubectl.kubernetes.io/last-applied-configuration")
						metaObj.GetObjectMeta().SetAnnotations(annotations)
					}
				}
				return obj, nil
			},
		},
	})
	if err != nil {
		l.Error("error creating manager", "error", err)
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
		KubernetesClientSet: clientSet,
		Logger:              operatorLogger,
		Client:              mgr.GetClient(),
		Scheme:              mgr.GetScheme(),
		Watched:             watcherSelector,
		OperatorService:     svc,
	}).SetupWithManager(mgr, watcherOptions, predicates.NewPodPredicate(operatorConfig.ExcludedNamespaces, nodeName)); err != nil {
		l.Error("error creating watcher", "error", err)
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		l.Error("error adding healthz check", "error", err)
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		l.Error("error adding ready check", "error", err)
		os.Exit(1)
	}
	l.Info("SBOM collector operator started successfully", "excluded_namespaces", operatorConfig.ExcludedNamespaces)

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		l.Error("error running manager", "error", err)
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

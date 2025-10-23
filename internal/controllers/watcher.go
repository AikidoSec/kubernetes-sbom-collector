package controllers

import (
	"context"
	"fmt"
	"strings"

	"aikidoSec.kubernetes-sbom-collector/internal/service"
	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	"aikidoSec.kubernetes-sbom-collector/pkg/sbom"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/uuid"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// Watcher reconciles a kubernetes resource
type Watcher struct {
	client.Client
	KubernetesClientSet *kubernetes.Clientset
	Logger              *logger.Logger
	Scheme              *runtime.Scheme
	Watched             models.WatcherSelector
	OperatorService     *service.Service
}

func (r *Watcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod v1.Pod
	switch err := r.Get(ctx, req.NamespacedName, &pod); {
	case errors.IsNotFound(err):
		return ctrl.Result{}, nil
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting object", "watcherError", "name", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get referenced object %v: %w", req.NamespacedName, err)
	}

	keychain, err := r.getKeychain(ctx, pod)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error getting keychain", "sbomWatcherError")
		return ctrl.Result{}, err
	}

	images := listPodUsedImages(&pod)
	r.Logger.LogInfo("found images in pod", "pod", pod.Name, "namespace", pod.Namespace, "imageCount", len(images))
	for k, v := range images {
		r.Logger.LogInfo("found image in pod", "pod", pod.Name, "namespace", pod.Namespace, "image", k, "sha", v)
		if v == "" {
			r.Logger.LogWarning(fmt.Errorf("%s", k), "image with empty SHA value")
			continue
		}

		isProcessed, err := r.OperatorService.IsImageProcessed(ctx, k, v)
		if err != nil {
			r.Logger.ReportError(ctx, err, "error checking if image is processed", "sbomWatcherError", "image", k)
			continue
		}

		if isProcessed {
			continue
		}

		r.Logger.LogInfo("generating SBOM for image", "image", k)

		imageEncodedSBOM, err := sbom.GenerateImageSBOM(ctx, k, keychain)
		if err != nil {
			if strings.Contains(err.Error(), "UNAUTHORIZED") {
				r.Logger.ReportError(ctx, err, "unauthorized to pull image", "sbomWatcherError", "image", k)
				continue
			}
			r.Logger.ReportError(ctx, err, "error generating image SBOM", "sbomWatcherError", "image", k)
		}

		if imageEncodedSBOM == nil {
			continue
		}

		sbomPayload := models.SBOMPayload{
			Payload:  imageEncodedSBOM,
			Image:    k,
			ImageSHA: v,
		}

		if err := r.OperatorService.SendImageSBOM(ctx, sbomPayload); err != nil {
			r.Logger.ReportError(ctx, err, "error sending SBOM payload", "sbomSendError", "image", k)
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Watcher) SetupWithManager(mgr ctrl.Manager, opts controller.Options, predicate predicate.Predicate) error {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(r.Watched.GroupVersionKind)

	return ctrl.NewControllerManagedBy(mgr).
		Named("AikidoSBOMCollector"+"_"+uuid.NewString()).
		For(obj, builder.WithPredicates(predicate)).
		WithOptions(opts).
		Complete(r)
}

func (r *Watcher) getKeychain(ctx context.Context, pod v1.Pod) (authn.Keychain, error) {
	pullSecrets := make([]string, len(pod.Spec.ImagePullSecrets))
	for i, secret := range pod.Spec.ImagePullSecrets {
		pullSecrets[i] = secret.Name
	}

	return k8schain.New(
		ctx,
		r.KubernetesClientSet,
		k8schain.Options{
			Namespace:          pod.Namespace,
			ServiceAccountName: pod.Spec.ServiceAccountName,
			ImagePullSecrets:   pullSecrets,
			UseMountSecrets:    true,
		},
	)
}

func listPodUsedImages(p *v1.Pod) map[string]string {
	images := make(map[string]string)
	for _, c := range p.Status.ContainerStatuses {
		imageID := trimImageIDPrefix(c.ImageID)
		sha := getImageSHAFromID(imageID)
		images[imageID] = sha
	}

	for _, c := range p.Status.InitContainerStatuses {
		imageID := trimImageIDPrefix(c.ImageID)
		sha := getImageSHAFromID(imageID)
		images[imageID] = sha
	}

	return images
}

func getImageSHAFromID(imageID string) string {
	imageComponents := strings.Split(imageID, "@")
	if len(imageComponents) < 2 {
		return imageComponents[0]
	}

	return imageComponents[1]
}

func trimImageIDPrefix(imageID string) string {
	imageIDComponents := strings.Split(imageID, "://")
	if len(imageIDComponents) > 1 {
		imageID = imageIDComponents[1]
	}

	return imageID
}

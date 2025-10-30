package controllers

import (
	"context"
	"fmt"
	"strings"

	"aikidoSec.kubernetes-sbom-collector/internal/service"
	"aikidoSec.kubernetes-sbom-collector/pkg/image"
	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	"aikidoSec.kubernetes-sbom-collector/pkg/sbom"
	"github.com/hashicorp/go-multierror"

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

var excludedRegistries = []string{"https://602401143452.dkr.ecr", "-artifactregistry.gcr.io/gke-release/gke-release"}

// Watcher reconciles a kubernetes Pod object.
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

	// Generate a map of container names to their image tags, as they are defined in the Pod spec.
	containersTags, err := ListImageReferencesByContainer(&pod)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error listing pod container image references", "sbomWatcherError", "pod", pod.Name, "namespace", pod.Namespace)
	}

	images, errs := ListPodUsedImages(&pod, containersTags)
	if errs != nil {
		r.Logger.ReportError(ctx, errs, "error listing pod used images", "sbomWatcherError", "pod", pod.Name, "namespace", pod.Namespace)
	}

	var processingErrors error
	// We're still processing the images that were found even if there were errors listing some of them.
	for _, img := range images {
		if img.Digest == "" {
			r.Logger.LogWarning(fmt.Errorf("%s", img.Name()), "image with empty SHA value")
			continue
		}

		shouldSkip := false
		for _, excludedRegistry := range excludedRegistries {
			if strings.Contains(img.ResolvedImageID, excludedRegistry) {
				shouldSkip = true
				break
			}
		}

		if shouldSkip {
			continue
		}

		isProcessed, err := r.OperatorService.IsImageProcessed(ctx, img.ShorthandName(), img.Digest)
		if err != nil {
			r.Logger.ReportError(ctx, err, "error checking if image is processed", "sbomWatcherError", "image", img.Name(), "sha", img.Digest)
			processingErrors = multierror.Append(processingErrors, err)
			continue
		}

		if isProcessed {
			continue
		}

		imageEncodedSBOM, err := sbom.GenerateImageSBOM(ctx, img, keychain, 0)
		if err != nil {
			if strings.Contains(err.Error(), "UNAUTHORIZED") {
				r.Logger.ReportError(ctx, err, "unauthorized to pull image", "sbomWatcherError", "pod", pod.Name, "namespace", pod.Namespace, "image", img.Name(), "sha", img.Digest)
				continue
			}
			r.Logger.ReportError(ctx, err, "error generating image SBOM", "sbomWatcherError", "pod", pod.Name, "namespace", pod.Namespace, "image", img.Name(), "sha", img.Digest)
		}

		if imageEncodedSBOM == nil {
			continue
		}

		sbomPayload := models.SBOMPayload{
			Payload: imageEncodedSBOM,
			Image:   img.ShorthandName(),
			Digest:  img.Digest,
			Tag:     img.Tag,
		}

		if err := r.OperatorService.SendImageSBOM(ctx, sbomPayload); err != nil {
			r.Logger.ReportError(ctx, err, "error sending SBOM payload", "sbomSendError", "image", img.Name(), "sha", img.Digest)
			processingErrors = multierror.Append(processingErrors, err)
		}
	}

	// If there were processing errors (either from checking the cache or from sending the SBOM), we return them so the controller can retry.
	return ctrl.Result{}, processingErrors
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

// ListPodUsedImages lists all images used by the given pod, including those in init containers and ephemeral containers.
// It uses the provided map of container names to image references and the containers statuses to resolve the image references.
func ListPodUsedImages(p *v1.Pod, containersTags map[string]models.ImageReference) ([]models.ImageReference, error) {
	var errs error
	images := make([]models.ImageReference, 0)
	for _, s := range p.Status.ContainerStatuses {
		img, err := GetPodImageFromStatus(s, containersTags)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		images = append(images, img)
	}

	for _, s := range p.Status.InitContainerStatuses {
		img, err := GetPodImageFromStatus(s, containersTags)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		images = append(images, img)
	}

	for _, s := range p.Status.EphemeralContainerStatuses {
		img, err := GetPodImageFromStatus(s, containersTags)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		images = append(images, img)
	}

	return images, errs
}

// GetPodImageFromStatus returns the image reference for a given container status.
// The function parses the image digest from the status ImageID field. It then looks up the container name in the provided map of container tags to get the full image reference.
// If the container name is not found in the map, it falls back to parsing the image reference from the ImageID field.
// If no tag is found in both the status and the pod spec, it defaults to "latest".
func GetPodImageFromStatus(s v1.ContainerStatus, containerTags map[string]models.ImageReference) (models.ImageReference, error) {
	digest := image.ParseImageDigest(s.ImageID)
	imageReference, ok := containerTags[s.Name]
	if ok {
		// Default to "latest" if no tag is found in both the status and the pod spec.
		if imageReference.Tag == "" {
			imageReference.Tag = "latest"
		}

		imageReference.Digest = digest
		imageReference.ResolvedImageID = s.ImageID
		imageReference.ResolvedImage = s.Image
		return imageReference, nil
	}

	imageReference, err := image.ParseImageReference(image.TrimImageIDPrefix(s.ImageID))
	if err != nil {
		return models.ImageReference{}, fmt.Errorf("error parsing image reference: %w", err)
	}

	// Default to "latest" if no tag is found in both the status and the pod spec.
	if imageReference.Tag == "" {
		imageReference.Tag = "latest"
	}
	imageReference.ResolvedImageID = s.ImageID
	imageReference.ResolvedImage = s.Image

	if imageReference.ReferenceType == models.DigestReference {
		return imageReference, nil
	}

	imageReference.Digest = digest

	return imageReference, nil
}

// ListImageReferencesByContainer lists image references for all containers in the given pod, including init containers and ephemeral containers.
// It returns a map of container names to their corresponding image references.
func ListImageReferencesByContainer(p *v1.Pod) (map[string]models.ImageReference, error) {
	var errs error
	containerImageTags := make(map[string]models.ImageReference)
	for _, c := range p.Spec.Containers {
		ref, err := image.ParseImageReference(c.Image)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("error parsing image reference for container %s: %w", c.Name, err))
			continue
		}

		containerImageTags[c.Name] = ref
	}

	for _, c := range p.Spec.InitContainers {
		ref, err := image.ParseImageReference(c.Image)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("error parsing image reference for init container %s: %w", c.Name, err))
			continue
		}

		containerImageTags[c.Name] = ref
	}

	for _, c := range p.Spec.EphemeralContainers {
		ref, err := image.ParseImageReference(c.Image)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("error parsing image reference for ephemeral container %s: %w", c.Name, err))
			continue
		}

		containerImageTags[c.Name] = ref
	}

	return containerImageTags, errs
}

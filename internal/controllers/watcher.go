package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"aikidoSec.kubernetes-sbom-collector/internal/service"
	"aikidoSec.kubernetes-sbom-collector/pkg/image"
	"aikidoSec.kubernetes-sbom-collector/pkg/imagefilter"
	"aikidoSec.kubernetes-sbom-collector/pkg/keychain"
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

const defaultRequeueAfter = 12 * time.Hour

var excludedRegistries = []string{
	"013241004608.dkr.ecr",
	"066635153087.dkr.ecr",
	"121268973566.dkr.ecr",
	"151742754352.dkr.ecr",
	"296578399912.dkr.ecr",
	"333609536671.dkr.ecr",
	"455263428931.dkr.ecr",
	"491585149902.dkr.ecr",
	"533267051163.dkr.ecr",
	"558608220178.dkr.ecr",
	"590381155156.dkr.ecr",
	"602401143452.dkr.ecr",
	"730335286997.dkr.ecr",
	"759879836304.dkr.ecr",
	"761377655185.dkr.ecr",
	"800184023465.dkr.ecr",
	"877085696533.dkr.ecr",
	"900612956339.dkr.ecr",
	"900889452093.dkr.ecr",
	"918309763551.dkr.ecr",
	"961992271922.dkr.ecr",
	"-artifactregistry.gcr.io/gke-release",
}

// Watcher reconciles a kubernetes Pod object.
type Watcher struct {
	client.Client
	KubernetesClientSet                *kubernetes.Clientset
	Logger                             *logger.Logger
	Scheme                             *runtime.Scheme
	Watched                            models.WatcherSelector
	OperatorService                    *service.Service
	HasSecretsPermission               bool
	CollectorNamespace                 string
	CollectorServiceAccountName        string
	CollectorServiceAccountPullSecrets []string
	RunningAsDaemonSet                 bool
	ExcludedImageNames                 imagefilter.NamePatterns
}

func (r *Watcher) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod v1.Pod
	switch err := r.Get(ctx, req.NamespacedName, &pod); {
	case errors.IsNotFound(err):
		return ctrl.Result{}, nil
	case err != nil:
		r.Logger.ReportError(ctx, err, "error getting object", "watcherError", "pod", req.Name, "namespace", req.Namespace)
		return ctrl.Result{}, fmt.Errorf("could not get referenced object %v: %w", req.NamespacedName, err)
	}

	keychain, err := r.getKeychain(ctx, pod)
	if err != nil {
		r.Logger.ReportError(ctx, err, "error getting keychain", "sbomWatcherError", "pod", pod.Name, "namespace", pod.Namespace)
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
	imagesReservedByOtherCollectors := 0
	// We still process the images that were found even if there were errors listing some of them.
	for _, img := range images {
		if img.Digest == "" {
			r.Logger.ReportError(ctx, fmt.Errorf("%s", img.Name()), "image with empty SHA value", "sbomWatcherError", "pod", pod.Name, "namespace", pod.Namespace, "imageID", img.ResolvedImageID, "tag", img.Tag)
			continue
		}

		shouldSkip := false
		for _, excludedRegistry := range excludedRegistries {
			if strings.Contains(img.ShorthandName(), excludedRegistry) {
				shouldSkip = true
				break
			}
		}

		if shouldSkip {
			continue
		}

		if r.ExcludedImageNames.Match(img.ShorthandName()) || r.ExcludedImageNames.Match(img.Name()) {
			continue
		}

		imageStatus, err := r.OperatorService.GetImageStatus(ctx, img.ShorthandName(), img.Digest)
		if err != nil {
			r.Logger.ReportError(ctx, err, "error checking if image is processed", "sbomWatcherError", "pod", pod.Name, "namespace", pod.Namespace, "image", img.Name(), "sha", img.Digest, "tag", img.Tag)
			processingErrors = multierror.Append(processingErrors, err)
			continue
		}

		if imageStatus.IsProcessed {
			continue
		}

		if imageStatus.IsBeingProcessedByAnotherCollector {
			// If this image is being processed by another collector replica, we'll requeue this pod later on.
			imagesReservedByOtherCollectors++
			continue
		}

		// Use the image mirror registry if it's defined
		if imageStatus.MirrorRepository != "" {
			mirrorImageReference, err := image.ParseImageReference(imageStatus.MirrorRepository)
			if err != nil {
				r.Logger.ReportError(ctx, err, "error parsing mirror image reference", "sbomWatcherError", "pod", pod.Name, "namespace", pod.Namespace, "image", img.Name(), "sha", img.Digest, "tag", img.Tag)
				continue
			}
			img.Registry = mirrorImageReference.Registry
			img.ShorthandRegistry = mirrorImageReference.ShorthandRegistry
			img.Repository = mirrorImageReference.Repository
			img.ShorthandRepository = mirrorImageReference.ShorthandRepository
		}

		imageEncodedSBOM, err := sbom.GenerateImageSBOM(ctx, r.Logger, r.RunningAsDaemonSet, img, keychain, 0)
		if err != nil {
			if strings.Contains(err.Error(), "UNAUTHORIZED") {
				r.Logger.ReportError(ctx, err, "unauthorized to pull image", "sbomWatcherError", "pod", pod.Name, "namespace", pod.Namespace, "image", img.Name(), "sha", img.Digest, "tag", img.Tag)
				continue
			}
			r.Logger.ReportError(ctx, err, "error generating image SBOM", "sbomWatcherError", "pod", pod.Name, "namespace", pod.Namespace, "image", img.Name(), "sha", img.Digest, "tag", img.Tag)
		}

		if imageEncodedSBOM == nil {
			continue
		}

		sbomPayload := models.SBOMPayload{
			Payload:     imageEncodedSBOM,
			Image:       img.ShorthandName(),
			Digest:      img.Digest,
			Tag:         img.Tag,
			PodSourceID: fmt.Sprintf("core/v1/Pod/%s/%s", pod.Namespace, pod.Name),
		}

		if err := r.OperatorService.SendImageSBOM(ctx, sbomPayload); err != nil {
			r.Logger.ReportError(ctx, err, "error sending SBOM payload", "sbomSendError", "pod", pod.Name, "namespace", pod.Namespace, "image", img.Name(), "sha", img.Digest, "tag", img.Tag)
			processingErrors = multierror.Append(processingErrors, err)
		}
	}

	// If there were processing errors (either from checking the cache or from sending the SBOM), we return them so the controller can retry.
	// This way the controller-runtime will do a retry with exponential backoff.
	if processingErrors != nil {
		return ctrl.Result{}, processingErrors
	}

	if imagesReservedByOtherCollectors > 0 {
		return ctrl.Result{RequeueAfter: time.Minute * 15}, nil
	}

	return ctrl.Result{RequeueAfter: defaultRequeueAfter}, nil
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
	keyChains := make([]authn.Keychain, 0, 5)

	if r.HasSecretsPermission {
		// Add image pull secrets only if the watcher has permission to access them.

		pullSecrets := make([]string, 0, len(pod.Spec.ImagePullSecrets))
		for _, secret := range pod.Spec.ImagePullSecrets {
			pullSecrets = append(pullSecrets, secret.Name)
		}

		serviceAccountPullSecrets, err := keychain.GetServiceAccountSecretNames(ctx, r.KubernetesClientSet, pod.Namespace, pod.Spec.ServiceAccountName)
		if err != nil {
			r.Logger.ReportError(ctx, err, "error getting pod service account pull secrets", "sbomKeychainError", "pod", pod.Name, "namespace", pod.Namespace)
		} else {
			pullSecrets = append(pullSecrets, serviceAccountPullSecrets...)
		}

		// Create pod-specific keychain
		podKeychain, err := keychain.CreateKeychainFromPullSecrets(ctx, r.KubernetesClientSet, pod.Namespace, pullSecrets)
		if err != nil {
			r.Logger.ReportError(ctx, err, "error creating pod keychain", "sbomKeychainError", "pod", pod.Name, "namespace", pod.Namespace)
		} else {
			keyChains = append(keyChains, podKeychain)
		}

		collectorSecretNames := append([]string{}, r.CollectorServiceAccountPullSecrets...)
		collectorServiceAccountSecrets, err := keychain.GetServiceAccountSecretNames(ctx, r.KubernetesClientSet, r.CollectorNamespace, r.CollectorServiceAccountName)
		if err != nil {
			r.Logger.ReportError(ctx, err, "error getting collector service account pull secrets", "sbomKeychainError", "pod", pod.Name, "namespace", pod.Namespace)
		} else {
			collectorSecretNames = collectorServiceAccountSecrets
		}

		collectorKeychain, err := keychain.CreateKeychainFromPullSecrets(ctx, r.KubernetesClientSet, r.CollectorNamespace, collectorSecretNames)
		if err != nil {
			r.Logger.ReportError(ctx, err, "error creating collector keychain", "sbomKeychainError", "pod", pod.Name, "namespace", pod.Namespace)
		} else {
			keyChains = append(keyChains, collectorKeychain)
		}
	} else {
		// No access to secrets, so no use in checking, use a NoClient instance to still verify cloud providers in-cluster authentication
		noClientChain, err := k8schain.NewNoClient(ctx)
		if err != nil {
			r.Logger.ReportError(ctx, err, "error creating noClientChain keychain", "sbomKeychainError", "pod", pod.Name, "namespace", pod.Namespace)
		} else {
			keyChains = append(keyChains, noClientChain)
		}
	}

	// Add keychain for mounted Docker config secrets and the default keychain
	keyChains = append(keyChains, keychain.CreateMountedSecretKeychain(ctx), authn.DefaultKeychain)
	return authn.NewMultiKeychain(keyChains...), nil
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
// If no tag is found in both the status and the pod spec, the tag is left empty.
func GetPodImageFromStatus(s v1.ContainerStatus, containerTags map[string]models.ImageReference) (models.ImageReference, error) {
	digest := image.ParseImageDigest(s.ImageID)
	imageReference, ok := containerTags[s.Name]
	if ok {
		imageReference.Digest = digest
		imageReference.ResolvedImageID = s.ImageID
		imageReference.ResolvedImage = s.Image
		return imageReference, nil
	}

	imageReference, err := image.ParseImageReference(image.TrimImageIDPrefix(s.ImageID))
	if err != nil {
		return models.ImageReference{}, fmt.Errorf("error parsing image reference: %w", err)
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

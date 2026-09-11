package imageresolver

import (
	"context"
	"fmt"

	"aikidoSec.kubernetes-sbom-collector/pkg/image"
	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	"github.com/hashicorp/go-multierror"
	v1 "k8s.io/api/core/v1"

	containerdClient "github.com/containerd/containerd/v2/client"
)

type Resolver struct {
	IsContainerdRuntime bool
	ContainerdClient    *containerdClient.Client
	Logger              *logger.Logger
}

func NewImageResolver(logger *logger.Logger, isContainerdRuntime bool, client *containerdClient.Client) *Resolver {
	return &Resolver{
		IsContainerdRuntime: isContainerdRuntime,
		Logger:              logger,
		ContainerdClient:    client,
	}
}

// ListPodUsedImages lists all images used by the given pod, including those in init containers and ephemeral containers.
// It uses the provided map of container names to image references and the containers statuses to resolve the image references.
func (r *Resolver) ListPodUsedImages(ctx context.Context, p *v1.Pod, containersTags map[string]models.ImageReference) ([]models.ImageReference, error) {
	var errs error
	images := make([]models.ImageReference, 0)
	for _, s := range p.Status.ContainerStatuses {
		img, err := r.GetPodImageFromStatus(s, containersTags)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		images = append(images, img)
	}

	for _, s := range p.Status.InitContainerStatuses {
		img, err := r.GetPodImageFromStatus(s, containersTags)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		images = append(images, img)
	}

	for _, s := range p.Status.EphemeralContainerStatuses {
		img, err := r.GetPodImageFromStatus(s, containersTags)
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
func (r *Resolver) GetPodImageFromStatus(s v1.ContainerStatus, containerTags map[string]models.ImageReference) (models.ImageReference, error) {
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
func (r *Resolver) ListImageReferencesByContainer(p *v1.Pod) (map[string]models.ImageReference, error) {
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

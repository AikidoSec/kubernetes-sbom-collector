package imageresolver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"aikidoSec.kubernetes-sbom-collector/pkg/image"
	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	stereoscopeImage "github.com/anchore/stereoscope/pkg/image"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/go-multierror"
	v1 "k8s.io/api/core/v1"

	containerdClient "github.com/containerd/containerd/v2/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// ContainerdIDPrefix is the scheme CRI puts on container IDs backed by containerd.
const ContainerdIDPrefix = "containerd://"

type RegistryImageInfo struct {
	ImageName     string
	ImageDigest   string
	ImagePlatform *stereoscopeImage.Platform
}

type Resolver struct {
	ContainerdClient *containerdClient.Client
	Logger           *logger.Logger
	NodeInfo         models.NodeInfo
}

func NewImageResolver(logger *logger.Logger, client *containerdClient.Client, nodeInfo models.NodeInfo) *Resolver {
	return &Resolver{
		Logger:           logger,
		ContainerdClient: client,
		NodeInfo:         nodeInfo,
	}
}

// isContainerdContainer reports whether the container is managed by containerd, based on the runtime
// scheme CRI sets on the container ID. This is per container, so mixed-runtime clusters resolve correctly.
func isContainerdContainer(containerID string) bool {
	return strings.HasPrefix(containerID, ContainerdIDPrefix)
}

// ListPodUsedImages lists all images used by the given pod, including those in init containers and ephemeral containers.
// It uses the provided map of container names to image references and the containers statuses to resolve the image references.
func (r *Resolver) ListPodUsedImages(ctx context.Context, p *v1.Pod, containersTags map[string]models.ImageReference) ([]models.ImageReference, error) {
	var errs error
	images := make([]models.ImageReference, 0)
	containersImages, err := r.ListImagesFromContainerStatuses(ctx, p.Status.ContainerStatuses, containersTags)
	if err != nil {
		errs = multierror.Append(errs, err)
	}
	images = append(images, containersImages...)

	initContainersImages, err := r.ListImagesFromContainerStatuses(ctx, p.Status.InitContainerStatuses, containersTags)
	if err != nil {
		errs = multierror.Append(errs, err)
	}
	images = append(images, initContainersImages...)

	ephemeralContainersImages, err := r.ListImagesFromContainerStatuses(ctx, p.Status.EphemeralContainerStatuses, containersTags)
	if err != nil {
		errs = multierror.Append(errs, err)
	}
	images = append(images, ephemeralContainersImages...)

	return images, errs
}

func (r *Resolver) ListImagesFromContainerStatuses(ctx context.Context, statuses []v1.ContainerStatus, containersTags map[string]models.ImageReference) ([]models.ImageReference, error) {
	var errs error
	images := make([]models.ImageReference, 0)
	for _, s := range statuses {
		img, err := r.GetPodImageFromStatus(s, containersTags)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		if r.ContainerdClient == nil || !isContainerdContainer(s.ContainerID) {
			images = append(images, img)
			continue
		}

		registryImageInfo, err := r.GetRegistryImageInfo(ctx, s.ContainerID)
		if err != nil {
			r.Logger.ReportError(ctx, err, fmt.Sprintf("error getting image name reference for container `%s`", s.ContainerID), "sbomCollectorImageResolver")
			images = append(images, img)
			continue
		}

		img.ImagePlatform = registryImageInfo.ImagePlatform
		if registryImageInfo.ImageDigest == "" {
			images = append(images, img)
			continue
		}

		ref, err := name.ParseReference(registryImageInfo.ImageName)
		if err != nil {
			r.Logger.ReportError(ctx, err, fmt.Sprintf("error parsing image name `%s`", registryImageInfo.ImageName), "sbomCollectorImageResolver")
			img.ImageNameReference = registryImageInfo.ImageName
			images = append(images, img)
			continue
		}
		candidate := ref.Context().Digest(registryImageInfo.ImageDigest).Name()
		if strings.HasPrefix(candidate, name.DefaultRegistry) {
			candidate = strings.TrimPrefix(candidate, "index.")
		}

		exists, err := r.ImageExistsInRegistry(ctx, candidate)
		if err != nil {
			r.Logger.ReportError(ctx, err, fmt.Sprintf("error checking if image `%s` exists in local registry", candidate), "sbomCollectorImageResolver")
			img.ImageNameReference = registryImageInfo.ImageName
			images = append(images, img)
			continue
		}

		if exists {
			img.ImageNameReference = candidate
		} else if registryImageInfo.ImageName != "" {
			// If we can't find the image based on the image@digest format, we'll fall back to the image name returned by the container info.
			img.ImageNameReference = registryImageInfo.ImageName
		}

		images = append(images, img)
	}

	return images, errs
}

func (r *Resolver) ImageExistsInRegistry(ctx context.Context, reference string) (bool, error) {
	info, err := r.ContainerdClient.GetImage(ctx, reference)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return info != nil, nil
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
		imageReference.ImageNameReference = imageReference.NameWithDigest()
		return imageReference, nil
	}

	imageReference, err := image.ParseImageReference(image.TrimImageIDPrefix(s.ImageID))
	if err != nil {
		return models.ImageReference{}, fmt.Errorf("error parsing image reference: %w", err)
	}

	imageReference.ResolvedImageID = s.ImageID
	imageReference.ResolvedImage = s.Image

	if imageReference.ReferenceType != models.DigestReference {
		imageReference.Digest = digest
	}
	imageReference.ImageNameReference = imageReference.NameWithDigest()

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

func (r *Resolver) GetRegistryImageInfo(ctx context.Context, containerID string) (RegistryImageInfo, error) {
	if r.ContainerdClient == nil || !isContainerdContainer(containerID) {
		return RegistryImageInfo{}, nil
	}

	info, err := r.ContainerdClient.LoadContainer(ctx, strings.TrimPrefix(containerID, ContainerdIDPrefix))
	if err != nil {
		return RegistryImageInfo{}, fmt.Errorf("error loading container %s: %w", containerID, err)
	}

	img, err := info.Image(ctx)
	if err != nil {
		return RegistryImageInfo{}, fmt.Errorf("error loading image %s: %w", containerID, err)
	}

	imagePlatform, err := r.GetImagePlatform(ctx, img)
	if err != nil {
		r.Logger.ReportError(ctx, err, fmt.Sprintf("error getting image platform for image %s", img.Name()), "sbomCollectorImageResolver")
	}

	return RegistryImageInfo{
		ImageName:     img.Name(),
		ImageDigest:   img.Target().Digest.String(),
		ImagePlatform: imagePlatform,
	}, nil
}

func (r *Resolver) GetImagePlatform(ctx context.Context, img containerdClient.Image) (*stereoscopeImage.Platform, error) {
	target := img.Target()

	switch target.MediaType {
	case images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		return r.getImagePlatformFromIndex(ctx, img.Name(), target)

	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		return r.getImagePlatformFromManifest(ctx, img.Name(), target)

	default:
		return nil, fmt.Errorf("unsupported image target media type %q for image %q", target.MediaType, img.Name())
	}
}

func (r *Resolver) getImagePlatformFromIndex(ctx context.Context, imageName string, target ocispec.Descriptor) (*stereoscopeImage.Platform, error) {
	blob, err := content.ReadBlob(ctx, r.ContainerdClient.ContentStore(), target)
	if err != nil {
		return nil, fmt.Errorf("error reading image `%s` blob: %w", imageName, err)
	}

	var index ocispec.Index
	if err = json.Unmarshal(blob, &index); err != nil {
		return nil, fmt.Errorf("error unmarshalling image `%s` index: %w", imageName, err)
	}

	wanted := ocispec.Platform{
		OS:           r.NodeInfo.OperatingSystem,
		Architecture: r.NodeInfo.Architecture,
	}

	matcher := platforms.NewMatcher(wanted)

	for _, manifest := range index.Manifests {
		if manifest.Platform == nil {
			continue
		}

		if !matcher.Match(*manifest.Platform) {
			continue
		}

		return &stereoscopeImage.Platform{
			OS:           manifest.Platform.OS,
			Architecture: manifest.Platform.Architecture,
			Variant:      manifest.Platform.Variant,
		}, nil
	}

	return nil, nil
}

func (r *Resolver) getImagePlatformFromManifest(ctx context.Context, imageName string, target ocispec.Descriptor) (*stereoscopeImage.Platform, error) {
	blob, err := content.ReadBlob(ctx, r.ContainerdClient.ContentStore(), target)
	if err != nil {
		return nil, fmt.Errorf("error reading image manifest %s: %w", target.Digest, err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(blob, &manifest); err != nil {
		return nil, fmt.Errorf("error unmarshalling image %q manifest: %w", imageName, err)
	}

	configBlob, err := content.ReadBlob(ctx, r.ContainerdClient.ContentStore(), manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("error reading image config %s: %w", manifest.Config.Digest, err)
	}

	var platform ocispec.Platform
	if err := json.Unmarshal(configBlob, &platform); err != nil {
		return nil, fmt.Errorf("error unmarshalling image %q config platform: %w", imageName, err)
	}

	if platform.OS == "" || platform.Architecture == "" {
		return nil, nil
	}

	return &stereoscopeImage.Platform{
		OS:           platform.OS,
		Architecture: platform.Architecture,
		Variant:      platform.Variant,
	}, nil
}

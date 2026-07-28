package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	"github.com/anchore/syft/syft/source"
	containerdClient "github.com/containerd/containerd/v2/client"
	containerdDefaults "github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	dockerClient "github.com/moby/moby/client"
)

const (
	defaultContainerdNamespace = "k8s.io"
	containerdRuntime          = "containerd"
	dockerRuntime              = "docker"
	crioRuntime                = "cri-o"
)

type ImageSBOMResult struct {
	EncodedSBOM    []byte
	ImageSizeBytes int64
	UpdatedAt      time.Time
}

type imageConfig struct {
	Created time.Time `json:"created"`
}

func GetImageSizeAndTimestamp(ctx context.Context, log *logger.Logger, runningAsDaemonSet bool, image models.ImageReference, description source.Description) (int64, time.Time, error) {
	// Fetch the image Size and Created timestamp from the Syft description.
	imageMetadata, ok := description.Metadata.(source.ImageMetadata)
	if !ok {
		return 0, time.Time{}, fmt.Errorf("image metadata is not of type ImageMetadata")
	}
	imageSizeBytes := imageMetadata.Size

	// When running as a DaemonSet, try to read the image updated timestamp from the local image store.
	if runningAsDaemonSet {
		lastPushedAt, err := GetImageUpdatedAtFromLocalImageStore(ctx, image)
		if err != nil {
			log.LogWarning(err, "unable to read image timestamp from local image store, using Syft created timestamp")
		} else if !lastPushedAt.IsZero() {
			return imageSizeBytes, lastPushedAt, nil
		}
	}

	// Fallback to Syft RawConfig Created field if we can't get any timestamp from the local store.
	imageConfigCreatedAt, imageConfigErr := GetImageCreatedAtFromRawConfig(imageMetadata.RawConfig)
	if imageConfigErr != nil {
		return imageSizeBytes, time.Time{}, imageConfigErr
	}

	return imageSizeBytes, imageConfigCreatedAt, nil
}

func GetImageCreatedAtFromRawConfig(rawConfig []byte) (time.Time, error) {
	if len(rawConfig) == 0 {
		return time.Time{}, fmt.Errorf("image created timestamp unavailable")
	}

	var cfg imageConfig
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return time.Time{}, fmt.Errorf("error parsing image raw config: %w", err)
	}

	if cfg.Created.IsZero() {
		return time.Time{}, nil
	}

	return cfg.Created, nil
}

func GetImageUpdatedAtFromLocalImageStore(ctx context.Context, image models.ImageReference) (time.Time, error) {
	switch image.ContainerRuntime {
	default:
		return GetImageUpdatedAtFromContainerd(ctx, image)
	case dockerRuntime:
		return GetImageUpdatedAtFromDocker(ctx, image)
	case crioRuntime:
		// CRI-O does not expose a local image updated timestamp.
		return time.Time{}, nil
	}
}

func GetImageUpdatedAtFromContainerd(ctx context.Context, image models.ImageReference) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client, err := containerdClient.New(containerdAddress(), containerdClient.WithDefaultNamespace(containerdNamespace()))
	if err != nil {
		return time.Time{}, fmt.Errorf("error connecting to containerd: %w", err)
	}
	defer client.Close()

	ctx = namespaces.WithNamespace(ctx, containerdNamespace())

	if img, err := client.ImageService().Get(ctx, image.String()); err == nil {
		if !img.UpdatedAt.IsZero() {
			return img.UpdatedAt, nil
		}
	}

	images, err := client.ImageService().List(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("error listing containerd images: %w", err)
	}

	for _, img := range images {
		if img.Target.Digest.String() == image.Digest && !img.UpdatedAt.IsZero() {
			return img.UpdatedAt, nil
		}
	}

	return time.Time{}, fmt.Errorf("containerd image digest %s was not found", image.Digest)
}

func GetImageUpdatedAtFromDocker(ctx context.Context, image models.ImageReference) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client, err := dockerClient.New(dockerClient.FromEnv)
	if err != nil {
		return time.Time{}, fmt.Errorf("error connecting to docker: %w", err)
	}
	defer client.Close()

	var lastErr error
	for _, ref := range dockerImageInspectReferences(image) {
		if ref == "" {
			continue
		}

		inspect, err := client.ImageInspect(ctx, ref)
		if err != nil {
			lastErr = fmt.Errorf("error inspecting docker image %s: %w", ref, err)
			continue
		}

		if !inspect.Metadata.LastTagTime.IsZero() {
			return inspect.Metadata.LastTagTime, nil
		}

		if inspect.Created != "" {
			createdAt, err := time.Parse(time.RFC3339Nano, inspect.Created)
			if err != nil {
				return time.Time{}, fmt.Errorf("error parsing docker image %s created time: %w", ref, err)
			}

			return createdAt, nil
		}
	}

	if lastErr != nil {
		return time.Time{}, fmt.Errorf("image updated timestamp unavailable for docker image %s: %w", image.String(), lastErr)
	}

	return time.Time{}, fmt.Errorf("image updated timestamp unavailable for docker image %s", image.String())
}

// dockerImageInspectReferences returns a list of image references that docker can use to look up the image
func dockerImageInspectReferences(image models.ImageReference) []string {
	refs := make([]string, 3)
	refs[0] = image.String()
	refs[1] = image.ResolvedImage

	if components := strings.Split(image.ResolvedImageID, "//"); len(components) == 2 {
		refs[2] = components[1]
	}

	return refs
}

func containerdAddress() string {
	if address := strings.TrimSpace(os.Getenv("CONTAINERD_ADDRESS")); address != "" {
		return address
	}

	return containerdDefaults.DefaultAddress
}

func containerdNamespace() string {
	if namespace := strings.TrimSpace(os.Getenv("CONTAINERD_NAMESPACE")); namespace != "" {
		return namespace
	}

	return defaultContainerdNamespace
}

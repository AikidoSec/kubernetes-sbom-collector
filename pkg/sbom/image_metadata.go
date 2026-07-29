package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	"github.com/anchore/syft/syft/source"
	containerdClient "github.com/containerd/containerd/v2/client"
	containerdDefaults "github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	dockerClient "github.com/moby/moby/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	defaultContainerdNamespace = "k8s.io"
	defaultCRIOEndpoint        = "unix:///var/run/crio/crio.sock"
	remoteTagLookupConcurrency = 8
	containerdRuntime          = "containerd"
	dockerRuntime              = "docker"
	crioRuntime                = "cri-o"
)

type ImageSBOMResult struct {
	EncodedSBOM    []byte
	ImageSizeBytes int64
	UpdatedAt      time.Time
	AdditionalTags []string
}

type ImageMetadata struct {
	ImageSizeBytes int64
	UpdatedAt      time.Time
	AdditionalTags []string
}

type imageConfig struct {
	Created time.Time `json:"created"`
}

func GetImageSizeAndTimestamp(ctx context.Context, log *logger.Logger, runningAsDaemonSet bool, image models.ImageReference, keychain authn.Keychain, description source.Description) (ImageMetadata, error) {
	// Fetch the image Size and Created timestamp from the Syft description.
	imageMetadata, ok := description.Metadata.(source.ImageMetadata)
	if !ok {
		return ImageMetadata{}, fmt.Errorf("image metadata is not of type ImageMetadata")
	}
	imageSizeBytes := imageMetadata.Size
	metadata := ImageMetadata{
		ImageSizeBytes: imageSizeBytes,
	}

	// When running as a DaemonSet, try to read the image updated timestamp from the local image store.
	if runningAsDaemonSet {
		localStoreMetadata, err := GetImageUpdatedAtFromLocalImageStore(ctx, log, image)
		if err != nil {
			log.LogWarning(err, "unable to read image timestamp from local image store, using Syft created timestamp")
		} else {
			if !localStoreMetadata.UpdatedAt.IsZero() {
				metadata.UpdatedAt = localStoreMetadata.UpdatedAt
			}
			if len(localStoreMetadata.AdditionalTags) > 0 {
				metadata.AdditionalTags = localStoreMetadata.AdditionalTags
			}

			if image.Tag != "" && !metadata.UpdatedAt.IsZero() {
				return metadata, nil
			}
		}
	}

	// Fallback to Syft RawConfig Created field if we can't get any timestamp from the local store.
	if metadata.UpdatedAt.IsZero() {
		imageConfigCreatedAt, imageConfigErr := GetImageCreatedAtFromRawConfig(imageMetadata.RawConfig)
		if imageConfigErr != nil {
			log.LogWarning(imageConfigErr, "unable to read image created timestamp from Syft metadata")
		} else {
			metadata.UpdatedAt = imageConfigCreatedAt
		}
	}
	// Fallback to remote registry call if the tag is empty
	if image.Tag == "" {
		tags, err := GetImageTagsFromRemoteRegistry(ctx, log, image, keychain)
		if err != nil {
			log.LogWarning(err, "unable to read image tag from remote registry")
		} else if len(tags) > 0 {
			metadata.AdditionalTags = tags
		}
	}

	return metadata, nil
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

func GetImageUpdatedAtFromLocalImageStore(ctx context.Context, log *logger.Logger, image models.ImageReference) (ImageMetadata, error) {
	switch image.ContainerRuntime {
	default:
		return GetImageMetadataFromContainerd(ctx, log, image)
	case dockerRuntime:
		return GetImageMetadataFromDocker(ctx, log, image)
	case crioRuntime:
		return GetImageMetadataFromCRIO(ctx, log, image)
	}
}

func GetImageMetadataFromContainerd(ctx context.Context, log *logger.Logger, image models.ImageReference) (ImageMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client, err := containerdClient.New(containerdAddress(), containerdClient.WithDefaultNamespace(containerdNamespace()))
	if err != nil {
		return ImageMetadata{}, fmt.Errorf("error connecting to containerd: %w", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.LogWarning(err, "error closing containerd client")
		}
	}()

	ctx = namespaces.WithNamespace(ctx, containerdNamespace())

	var metadata ImageMetadata
	if img, err := client.ImageService().Get(ctx, image.String()); err == nil {
		metadata.UpdatedAt = img.UpdatedAt
	}

	images, err := client.ImageService().List(ctx)
	if err != nil {
		return ImageMetadata{}, fmt.Errorf("error listing containerd images: %w", err)
	}

	for _, img := range images {
		if img.Target.Digest.String() == image.Digest {
			if metadata.UpdatedAt.IsZero() && !img.UpdatedAt.IsZero() {
				metadata.UpdatedAt = img.UpdatedAt
			}
			metadata.AdditionalTags = append(metadata.AdditionalTags, tagsFromReferences([]string{img.Name})...)
		}
	}

	if !metadata.UpdatedAt.IsZero() || len(metadata.AdditionalTags) > 0 {
		return metadata, nil
	}

	return ImageMetadata{}, fmt.Errorf("containerd image digest %s was not found", image.Digest)
}

func GetImageMetadataFromDocker(ctx context.Context, log *logger.Logger, image models.ImageReference) (ImageMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client, err := dockerClient.New(dockerClient.FromEnv)
	if err != nil {
		return ImageMetadata{}, fmt.Errorf("error connecting to docker: %w", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.LogWarning(err, "error closing docker client")
		}
	}()

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

		updatedAt := time.Time{}
		if inspect.Created != "" {
			createdAt, err := time.Parse(time.RFC3339Nano, inspect.Created)
			if err != nil {
				return ImageMetadata{}, fmt.Errorf("error parsing docker image %s created time: %w", ref, err)
			}

			updatedAt = createdAt
		}

		if !inspect.Metadata.LastTagTime.IsZero() {
			updatedAt = inspect.Metadata.LastTagTime
		}

		return ImageMetadata{UpdatedAt: updatedAt, AdditionalTags: tagsFromReferences(inspect.RepoTags)}, nil
	}

	if lastErr != nil {
		return ImageMetadata{}, fmt.Errorf("image updated timestamp unavailable for docker image %s: %w", image.String(), lastErr)
	}

	return ImageMetadata{}, fmt.Errorf("image updated timestamp unavailable for docker image %s", image.String())
}

func GetImageMetadataFromCRIO(ctx context.Context, log *logger.Logger, image models.ImageReference) (ImageMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := newCRIConnection(crioEndpoint())
	if err != nil {
		return ImageMetadata{}, fmt.Errorf("error connecting to CRI-O: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.LogWarning(err, "error closing CRI-O connection")
		}
	}()

	imageService := runtimeapi.NewImageServiceClient(conn)
	response, err := imageService.ImageStatus(ctx, &runtimeapi.ImageStatusRequest{
		Image: &runtimeapi.ImageSpec{
			Image: image.String(),
		},
	})
	if err != nil {
		return ImageMetadata{}, fmt.Errorf("error listing CRI-O images: %w", err)
	}

	return ImageMetadata{AdditionalTags: tagsFromReferences(response.Image.GetRepoTags())}, nil
}

func newCRIConnection(endpoint string) (*grpc.ClientConn, error) {
	network := "unix"
	address := strings.TrimPrefix(endpoint, "unix://")

	if strings.HasPrefix(endpoint, "tcp://") {
		network = "tcp"
		address = strings.TrimPrefix(endpoint, "tcp://")
	}

	return grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		}),
	)
}

func GetImageTagsFromRemoteRegistry(ctx context.Context, log *logger.Logger, image models.ImageReference, keychain authn.Keychain) ([]string, error) {
	repo, err := name.NewRepository(image.Name())
	if err != nil {
		return nil, fmt.Errorf("error parsing image repository %s: %w", image.Name(), err)
	}

	options := []remote.Option{remote.WithContext(ctx)}
	if keychain != nil {
		options = append(options, remote.WithAuthFromKeychain(keychain))
	}

	tags, err := remote.List(repo, options...)
	if err != nil {
		return nil, fmt.Errorf("error listing image tags for repository %s: %w", repo.Name(), err)
	}

	matches := make([]string, 0)
	var matchesMu sync.Mutex
	semaphore := make(chan struct{}, remoteTagLookupConcurrency)

	var wg sync.WaitGroup
	for _, tag := range tags {
		if tag == "" {
			continue
		}

		wg.Go(func() {
			select {
			case <-ctx.Done():
				return
			case semaphore <- struct{}{}:
			}
			defer func() {
				<-semaphore
			}()

			desc, err := remote.Get(repo.Tag(tag), options...)
			if err != nil {
				log.LogWarning(err, "error getting remote image tag")
			}
			if !descriptorMatchesDigest(desc, image.Digest) {
				return
			}

			matchesMu.Lock()
			defer matchesMu.Unlock()
			matches = append(matches, tag)
		})
	}

	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return matches, nil
}

func descriptorMatchesDigest(desc *remote.Descriptor, digest string) bool {
	if desc == nil {
		return false
	}

	if desc.Digest.String() == digest {
		return true
	}

	index, err := desc.ImageIndex()
	if err != nil {
		return false
	}

	indexManifest, err := index.IndexManifest()
	if err != nil {
		return false
	}

	// Check if any of the platform specific digests matches the image
	for _, manifest := range indexManifest.Manifests {
		if manifest.Digest.String() == digest {
			return true
		}
	}

	return false
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

func crioEndpoint() string {
	if endpoint := strings.TrimSpace(os.Getenv("CRIO_ENDPOINT")); endpoint != "" {
		return endpoint
	}

	return defaultCRIOEndpoint
}

func tagsFromReferences(refs []string) []string {
	tags := make([]string, 0, len(refs))
	for _, ref := range refs {
		if tag := tagFromReference(ref); tag != "" {
			tags = append(tags, tag)
		}
	}

	return tags
}

func tagFromReference(ref string) string {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return ""
	}

	tag, ok := parsedRef.(name.Tag)
	if !ok {
		return ""
	}

	return tag.TagStr()
}

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
	latestTag                  = "latest"
)

type ImageSBOMResult struct {
	EncodedSBOM    []byte
	ImageSizeBytes int64
	UpdatedAt      time.Time
	Tag            string
}

type ImageMetadata struct {
	ImageSizeBytes int64
	UpdatedAt      time.Time
	Tag            string
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
			if localStoreMetadata.Tag != "" {
				metadata.Tag = localStoreMetadata.Tag
			}

			if metadata.Tag != "" && !metadata.UpdatedAt.IsZero() {
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
	if metadata.Tag == "" && image.Tag == "" {
		tag, err := GetImageTagFromRemoteRegistry(ctx, image, keychain)
		if err != nil {
			log.LogWarning(err, "unable to read image tag from remote registry")
		} else {
			metadata.Tag = tag
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
		tag := identifyLatestTag([]string{img.Name})
		metadata.UpdatedAt = img.UpdatedAt
		metadata.Tag = tag
		if !metadata.UpdatedAt.IsZero() && metadata.Tag != "" {
			return metadata, nil
		}
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
			if metadata.Tag == "" {
				metadata.Tag = identifyLatestTag([]string{img.Name})
			}
			if !metadata.UpdatedAt.IsZero() && metadata.Tag != "" {
				return metadata, nil
			}
		}
	}

	if !metadata.UpdatedAt.IsZero() || metadata.Tag != "" {
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

		tag := identifyLatestTag(inspect.RepoTags)
		return ImageMetadata{UpdatedAt: updatedAt, Tag: tag}, nil
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

	return ImageMetadata{Tag: identifyLatestTag(response.Image.GetRepoTags())}, nil
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

func GetImageTagFromRemoteRegistry(ctx context.Context, image models.ImageReference, keychain authn.Keychain) (string, error) {
	repo, err := name.NewRepository(image.Name())
	if err != nil {
		return "", fmt.Errorf("error parsing image repository %s: %w", image.Name(), err)
	}

	options := []remote.Option{remote.WithContext(ctx)}
	if keychain != nil {
		options = append(options, remote.WithAuthFromKeychain(keychain))
	}

	tags, err := remote.List(repo, options...)
	if err != nil {
		return "", fmt.Errorf("error listing image tags for repository %s: %w", repo.Name(), err)
	}

	tagsCh := make(chan string)
	resultCh := make(chan string, 1)
	wg := startRemoteTagLookupWorkers(tagsCh, resultCh, repo, image.Digest, options)

	for _, tag := range tags {
		if tag == "" || tag == "latest" {
			continue
		}

		select {
		case result := <-resultCh:
			close(tagsCh)
			wg.Wait()
			return result, nil
		case <-ctx.Done():
			close(tagsCh)
			wg.Wait()
			return "", ctx.Err()
		case tagsCh <- tag:
		}
	}

	close(tagsCh)
	wg.Wait()

	select {
	case result := <-resultCh:
		return result, nil
	default:
	}

	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	return "", nil
}

func startRemoteTagLookupWorkers(tagsCh <-chan string, resultCh chan<- string, repo name.Repository, digest string, options []remote.Option) *sync.WaitGroup {
	var wg sync.WaitGroup
	for range remoteTagLookupConcurrency {
		wg.Go(func() {
			for tag := range tagsCh {
				desc, err := remote.Get(repo.Tag(tag), options...)
				if err != nil {
					continue
				}
				if !descriptorMatchesDigest(desc, digest) {
					continue
				}

				select {
				case resultCh <- tag:
				default:
				}
				return
			}
		})
	}

	return &wg
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

func identifyLatestTag(tags []string) string {
	if len(tags) == 1 && tagFromReference(tags[0]) == latestTag {
		return latestTag
	}

	for _, tag := range tags {
		tag = tagFromReference(tag)
		if tag == "" || tag == latestTag {
			continue
		}

		return tag
	}

	return ""
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

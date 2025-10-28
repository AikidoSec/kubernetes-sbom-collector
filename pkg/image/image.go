package image

import (
	"fmt"
	"strings"

	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	"github.com/google/go-containerregistry/pkg/name"
)

const (
	DefaultShorthandDockerRegistry = "docker/"
	DefaultDockerRegistry          = "docker.io/"
	DefaultDockerIndexRegistry     = name.DefaultRegistry + "/"
	DefaultDockerNamespace         = "library/"
)

var ErrInvalidImageReference = fmt.Errorf("invalid image reference")

func ParseImageReference(image string) (models.ImageReference, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return models.ImageReference{}, fmt.Errorf("%w: %w", ErrInvalidImageReference, err)
	}

	switch r := ref.(type) {
	case name.Tag:
		return models.ImageReference{
			Registry:            r.Context().RegistryStr(),
			Repository:          r.RepositoryStr(),
			ShorthandRepository: normalizeRepositoryName(r.RepositoryStr()),
			Tag:                 r.TagStr(),
			Digest:              "",
			ReferenceType:       models.TagReference,
		}, nil
	case name.Digest:
		// References of type Digest do not allow us to extract the tag but the image might still contain it.
		parts := strings.Split(image, "@")
		if len(parts) != 2 {
			return models.ImageReference{}, fmt.Errorf("%w: invalid digest format", ErrInvalidImageReference)
		}
		base := parts[0]

		var imageTag string
		tag, err := name.NewTag(base)
		if err == nil {
			imageTag = tag.TagStr()
		}
		return models.ImageReference{
			Registry:            r.Context().RegistryStr(),
			Repository:          r.RepositoryStr(),
			ShorthandRepository: normalizeRepositoryName(r.RepositoryStr()),
			Tag:                 imageTag,
			Digest:              r.DigestStr(),
			ReferenceType:       models.DigestReference,
		}, nil
	default:
		return models.ImageReference{}, fmt.Errorf("unsupported reference type: %s", r.Context().RegistryStr())
	}
}

func ParseImageDigest(imageID string) string {
	imageID = TrimImageIDPrefix(imageID)
	imageComponents := strings.Split(imageID, "@")

	// The image ID might contain only the digest without the image name.
	// For example if the image is pulled directly from the local registry.
	if len(imageComponents) == 1 {
		return imageID
	}

	return imageComponents[1]
}

func TrimImageIDPrefix(imageID string) string {
	imageIDComponents := strings.Split(imageID, "://")
	if len(imageIDComponents) > 1 {
		imageID = imageIDComponents[1]
	}

	return imageID
}

func normalizeRepositoryName(repository string) string {
	repository = strings.TrimPrefix(repository, DefaultShorthandDockerRegistry)
	repository = strings.TrimPrefix(repository, DefaultDockerNamespace)
	repository = strings.TrimPrefix(repository, DefaultDockerIndexRegistry)
	repository = strings.TrimPrefix(repository, DefaultDockerRegistry)

	// The full repository name might contain the project name.
	// E.g., europe-west1-docker.pkg.dev/project-name/httpd/httpd -> we want httpd/httpd
	// See https://cloud.google.com/artifact-registry/docs/docker/names#containers
	parts := strings.Split(repository, "/")
	if len(parts) > 2 {
		repository = strings.Join(parts[1:], "/")
	}

	return repository
}

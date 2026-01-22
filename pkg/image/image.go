package image

import (
	"fmt"
	"slices"
	"strings"

	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	"github.com/google/go-containerregistry/pkg/name"
)

const (
	DefaultShorthandDockerRegistry = "docker"
	DefaultDockerRegistry          = "docker.io"
	DefaultDockerNamespace         = "library"
)

var prefixes = []string{DefaultShorthandDockerRegistry, DefaultDockerNamespace, name.DefaultRegistry, DefaultDockerRegistry}

var ErrInvalidImageReference = fmt.Errorf("invalid image reference")

func ParseImageReference(image string) (models.ImageReference, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return models.ImageReference{}, fmt.Errorf("%w: %w", ErrInvalidImageReference, err)
	}

	switch r := ref.(type) {
	case name.Tag:
		registry := parseImageRegistry(r.Context().RegistryStr(), image)
		return models.ImageReference{
			Registry:            registry,
			ShorthandRegistry:   normalizeRegistryName(registry),
			Repository:          parseImageRepository(r.RepositoryStr(), registry),
			ShorthandRepository: normalizeRepositoryName(r.RepositoryStr(), registry),
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
		// Only extract the tag if it was explicitly provided in the original image (contains a colon)
		lastSlash := strings.LastIndex(base, "/")
		namePart := base
		if lastSlash != -1 {
			namePart = base[lastSlash+1:]
		}
		if strings.Contains(namePart, ":") {
			tag, err := name.NewTag(base)
			if err == nil {
				imageTag = tag.TagStr()
			}
		}
		registry := parseImageRegistry(r.Context().RegistryStr(), image)
		return models.ImageReference{
			Registry:            registry,
			ShorthandRegistry:   normalizeRegistryName(registry),
			Repository:          parseImageRepository(r.RepositoryStr(), registry),
			ShorthandRepository: normalizeRepositoryName(r.RepositoryStr(), registry),
			Tag:                 imageTag,
			Digest:              r.DigestStr(),
			ReferenceType:       models.DigestReference,
		}, nil
	default:
		return models.ImageReference{}, fmt.Errorf("unsupported reference type: %s", r.Context().RegistryStr())
	}
}

func parseImageRegistry(registry, originalImage string) string {
	// For Docker, return an empty string if the registry is the default registry and the image is not using the full name.
	if registry == name.DefaultRegistry &&
		!strings.HasPrefix(originalImage, name.DefaultRegistry) &&
		!strings.HasPrefix(originalImage, DefaultDockerRegistry) {
		return ""
	}

	// For Google Artifact Registry, include the project name in the registry.
	// E.g., europe-west1-docker.pkg.dev/project-name/httpd/httpd
	// Registry should be: europe-west1-docker.pkg.dev/project-name
	// See https://cloud.google.com/artifact-registry/docs/docker/names#containers
	if strings.HasSuffix(registry, ".pkg.dev") {
		// Extract the part after the registry from the original image
		if idx := strings.Index(originalImage, registry); idx != -1 {
			start := idx + len(registry) + 1 // +1 for the '/'
			if start <= len(originalImage) {
				afterRegistry := originalImage[start:]
				// Get the first component (project name)
				if before, _, ok := strings.Cut(afterRegistry, "/"); ok {
					projectName := before
					return registry + "/" + projectName
				}
			}
		}
	}

	return registry
}

func parseImageRepository(repository, registry string) string {
	// Strip the default Docker prefixes for Docker Hub and ECR public registry
	if registry == "" ||
		slices.Contains(prefixes, registry) ||
		strings.Contains(registry, "ecr.aws") {
		// Docker official images published to the ECR public registry have these prefixes.
		// E.g., https://gallery.ecr.aws/docker/library/nginx
		repository = strings.TrimPrefix(repository, DefaultShorthandDockerRegistry+"/")
		repository = strings.TrimPrefix(repository, DefaultDockerNamespace+"/")
	}

	return stripGARProjectName(repository, registry)
}

func stripGARProjectName(repository, registry string) string {
	// The full repository name might contain the project name for Google Artifact Registry.
	// E.g., europe-west1-docker.pkg.dev/project-name/httpd/httpd -> we want httpd/httpd
	// See https://cloud.google.com/artifact-registry/docs/docker/names#containers
	// Only apply this logic for GAR registries (containing .pkg.dev)
	if strings.Contains(registry, ".pkg.dev") {
		parts := strings.Split(repository, "/")
		if len(parts) > 2 {
			return strings.Join(parts[1:], "/")
		}
	}

	return repository
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

func normalizeRegistryName(registry string) string {
	// For Docker default registry, return empty string
	if registry == "" {
		return ""
	}

	if slices.Contains(prefixes, registry) {
		return ""
	}

	// For all other registries, return as-is
	return registry
}

func normalizeRepositoryName(repository, registry string) string {
	for _, v := range prefixes {
		repository = removePrefix(repository, v+"/")
	}

	return stripGARProjectName(repository, registry)
}

func removePrefix(s, prefix string) string {
	s = strings.TrimPrefix(s, prefix)

	return s
}

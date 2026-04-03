package sbom

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	stereoscopeImage "github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/hashicorp/go-multierror"

	_ "modernc.org/sqlite"
)

var tempDirectories = []string{"/tmp", "/.ecr"}
var sourcesTags = []string{"docker", "containerd", "registry"}

const (
	registrySource = "registry"
	maxRetries     = 15
)

func GenerateImageSBOM(ctx context.Context, logger *logger.Logger, runningAsDaemonSet bool, image models.ImageReference, keychain authn.Keychain, retry int) (encodedSBOM []byte, err error) {
	defer func() {
		if cleanupErr := cleanupDirectories(tempDirectories); cleanupErr != nil {
			err = multierror.Append(err, cleanupErr)
		}
	}()

	sources := sourcesTags
	if !runningAsDaemonSet {
		sources = []string{registrySource}
	}

	src, err := syft.GetSource(ctx, image.String(), syft.DefaultGetSourceConfig().WithRegistryOptions(&stereoscopeImage.RegistryOptions{Keychain: keychain}).WithSources(sources...))
	if err != nil {
		if strings.Contains(err.Error(), "TOOMANYREQUESTS: Rate exceeded") {
			if retry > maxRetries {
				return nil, fmt.Errorf("error getting image source: %w", err)
			}
			// Exponential backoff retry for rate limiting errors.
			time.Sleep(time.Duration(retry+1) * 5 * time.Second)
			return GenerateImageSBOM(ctx, logger, runningAsDaemonSet, image, keychain, retry+1)
		}

		return nil, fmt.Errorf("error getting image source: %w", err)
	}

	createSBOMConfig := LoadConfig(ctx, logger)
	sbom, err := syft.CreateSBOM(ctx, src, createSBOMConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating SBOM: %w", err)
	}

	if sbom == nil {
		return nil, fmt.Errorf("invalid sbom value")
	}

	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, fmt.Errorf("error creating cyclonedx encoder: %w", err)
	}

	encodedSBOM, err = format.Encode(*sbom, encoder)
	if err != nil {
		return nil, fmt.Errorf("error encoding SBOM: %w", err)
	}

	return encodedSBOM, nil
}

func cleanupDirectories(directories []string) error {
	for _, directory := range directories {
		err := removeDirectoryContents(directory)
		if err != nil {
			return fmt.Errorf("error removing directory contents: %w", err)
		}
	}

	return nil
}

func removeDirectoryContents(directory string) (err error) {
	d, err := os.Open(filepath.Clean(directory))
	if err != nil {
		return fmt.Errorf("error opening directory %s: %w", directory, err)
	}

	defer func() {
		if closeErr := d.Close(); closeErr != nil {
			err = multierror.Append(err, fmt.Errorf("error cleaning up temp dir: %w", closeErr))
		}
	}()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("error reading directory %s: %w", directory, err)
	}

	for _, name := range names {
		err = os.RemoveAll(filepath.Join(directory, name))
		if err != nil {
			return fmt.Errorf("error removing file %s: %w", filepath.Join(directory, name), err)
		}
	}

	return nil
}

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
	"github.com/anchore/syft/syft/format/syftjson"
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

type ImageSBOMConfig struct {
	IsRunningAsDaemonSet bool
	Image                models.ImageReference
	Keychain             authn.Keychain
	NodeInfo             models.NodeInfo
}

func GenerateImageSBOM(ctx context.Context, log *logger.Logger, retry int, imageCfg ImageSBOMConfig) (result ImageSBOMResult, err error) {
	defer func() {
		if cleanupErr := cleanupDirectories(tempDirectories); cleanupErr != nil {
			err = multierror.Append(err, cleanupErr)
		}
	}()

	sources := sourcesTags
	if !imageCfg.IsRunningAsDaemonSet {
		sources = []string{registrySource}
	}

	config := loadConfig(ctx, log)
	var createSBOMConfig *syft.CreateSBOMConfig
	if config != nil {
		createSBOMConfig = config.CreateSBOMConfig
		if len(config.From) > 0 {
			sources = config.From
		}
	}

	platform := imageCfg.Image.ImagePlatform
	if platform == nil && imageCfg.NodeInfo.OperatingSystem != "" && imageCfg.NodeInfo.Architecture != "" {
		platform = &stereoscopeImage.Platform{
			Architecture: imageCfg.NodeInfo.Architecture,
			OS:           imageCfg.NodeInfo.OperatingSystem,
		}
	}

	sourceConfig := syft.DefaultGetSourceConfig().
		WithRegistryOptions(&stereoscopeImage.RegistryOptions{Keychain: imageCfg.Keychain}).
		WithSources(sources...)

	if platform != nil && imageCfg.IsRunningAsDaemonSet {
		sourceConfig = sourceConfig.WithPlatform(platform)
	}

	return GenerateImageSBOMForConfigs(ctx, log, retry, imageCfg, createSBOMConfig, sourceConfig)
}

func GenerateImageSBOMForConfigs(ctx context.Context, log *logger.Logger, retry int, imageCfg ImageSBOMConfig, createSBOMConfig *syft.CreateSBOMConfig, sourceConfig *syft.GetSourceConfig) (result ImageSBOMResult, err error) {
	src, err := syft.GetSource(ctx, imageCfg.Image.ImageNameReference, sourceConfig)

	if err != nil {
		if strings.Contains(err.Error(), "TOOMANYREQUESTS: Rate exceeded") {
			if retry > maxRetries {
				return ImageSBOMResult{}, fmt.Errorf("error getting image source: %w", err)
			}
			// Exponential backoff retry for rate limiting errors.
			time.Sleep(time.Duration(retry+1) * 5 * time.Second)
			return GenerateImageSBOMForConfigs(ctx, log, retry+1, imageCfg, createSBOMConfig, sourceConfig)
		}

		// Syft may reject arm64 images whose config explicitly reports the v8 variant.
		if strings.Contains(err.Error(), `image has unexpected architecture "v8"`) && sourceConfig.SourceProviderConfig.Platform != nil && sourceConfig.SourceProviderConfig.Platform.Variant == "" {
			sourceConfig = sourceConfig.WithPlatform(&stereoscopeImage.Platform{
				Architecture: sourceConfig.SourceProviderConfig.Platform.Architecture,
				OS:           sourceConfig.SourceProviderConfig.Platform.OS,
				Variant:      "v8",
			})
			return GenerateImageSBOMForConfigs(ctx, log, retry, imageCfg, createSBOMConfig, sourceConfig)
		}

		// If the SBOM generation failed because we cannot find an image for the given platform, we retry without the platform constraint.
		if isPlatformError(err.Error()) && sourceConfig.SourceProviderConfig.Platform != nil {
			sourceConfig = sourceConfig.WithPlatform(nil)
			return GenerateImageSBOMForConfigs(ctx, log, retry, imageCfg, createSBOMConfig, sourceConfig)
		}

		return ImageSBOMResult{}, fmt.Errorf("error getting image source: %w", err)
	}

	sbom, err := syft.CreateSBOM(ctx, src, createSBOMConfig)
	if err != nil {
		return ImageSBOMResult{}, fmt.Errorf("error creating SBOM: %w", err)
	}

	if sbom == nil {
		return ImageSBOMResult{}, fmt.Errorf("invalid sbom value")
	}

	result.EncodedSBOM, err = format.Encode(*sbom, syftjson.NewFormatEncoder())
	if err != nil {
		return ImageSBOMResult{}, fmt.Errorf("error encoding SBOM: %w", err)
	}

	result.ImageSizeBytes, result.LastPushedAt, err = GetImageSizeAndTimestamp(ctx, log, runningAsDaemonSet, image, src.Describe())
	if err != nil {
		log.LogWarning(err, "error getting image metadata")
	}

	return result, nil
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

func isPlatformError(errVal string) bool {
	platformErrors := []string{
		"no child with platform",
		"no match for platform in manifest",
		"platform validation failed",
	}

	for _, platformError := range platformErrors {
		if strings.Contains(errVal, platformError) {
			return true
		}
	}

	return false
}

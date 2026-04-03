package sbom

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"github.com/anchore/syft/syft"
	"go.yaml.in/yaml/v3"
)

const (
	// MountedCreateSBOMConfigPath is the default path where a Syft CreateSBOM config can be mounted.
	// SYFT_CREATE_SBOM_CONFIG_PATH environment variable can be used to override this location.
	MountedCreateSBOMConfigPath = "/var/run/configmaps/syft/create-sbom-config.yaml"
	createSBOMConfigPathEnvVar  = "SYFT_CREATE_SBOM_CONFIG_PATH"
)

var (
	once sync.Once
	cfg  *syft.CreateSBOMConfig
	err  error
)

func LoadConfig(ctx context.Context, logger *logger.Logger) (*syft.CreateSBOMConfig, error) {
	once.Do(func() {
		cfg, err = readCreateSBOMConfig(createSBOMConfigPath())
		if err != nil {
			// Report the error once.
			logger.ReportError(ctx, err, "error loading Syft create SBOM config", "sbomConfigLoaderError")
			err = nil
		}
	})

	return cfg, err
}

func createSBOMConfigPath() string {
	if path, ok := os.LookupEnv(createSBOMConfigPathEnvVar); ok && strings.TrimSpace(path) != "" {
		return path
	}

	return MountedCreateSBOMConfigPath
}

func readCreateSBOMConfig(path string) (*syft.CreateSBOMConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading Syft create SBOM config %q: %w", path, err)
	}

	cfg := syft.DefaultCreateSBOMConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("error unmarshalling Syft create SBOM config %q: %w", path, err)
	}

	return cfg, nil
}

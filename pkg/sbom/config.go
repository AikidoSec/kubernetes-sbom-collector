package sbom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"aikidoSec.kubernetes-sbom-collector/pkg/logger"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
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

type createSBOMConfigFile struct {
	SelectCatalogers []string             `yaml:"select-catalogers"`
	JavaScript       javascriptConfigFile `yaml:"javascript"`
}

type javascriptConfigFile struct {
	IncludeDevDependencies bool `yaml:"include-dev-dependencies"`
}

func LoadConfig(ctx context.Context, logger *logger.Logger) *syft.CreateSBOMConfig {
	once.Do(func() {
		configPath := createSBOMConfigPath()
		cfg, err = readCreateSBOMConfig(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				logger.LogInfo(fmt.Sprintf("Syft config file not found in path `%s`, using default config", configPath))
			} else {
				// Report the error once.
				logger.ReportError(ctx, err, "error loading Syft create SBOM config", "sbomConfigLoaderError")
			}
		}
	})

	return cfg
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

	var fileConfig createSBOMConfigFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&fileConfig); err != nil {
		if errors.Is(err, io.EOF) {
			return syft.DefaultCreateSBOMConfig(), nil
		}
		return nil, fmt.Errorf("error unmarshalling Syft create SBOM config %q: %w", path, err)
	}

	cfg := syft.DefaultCreateSBOMConfig().
		WithCatalogerSelection(
			cataloging.NewSelectionRequest().
				WithExpression(fileConfig.SelectCatalogers...),
		)

	jsConfig := javascript.DefaultCatalogerConfig().
		WithIncludeDevDependencies(fileConfig.JavaScript.IncludeDevDependencies)

	cfg = cfg.WithPackagesConfig(
		pkgcataloging.DefaultConfig().
			WithJavascriptConfig(jsConfig),
	)

	return cfg, nil
}

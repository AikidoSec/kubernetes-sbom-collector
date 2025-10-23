package sbom

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	stereoscopeImage "github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/hashicorp/go-multierror"

	_ "modernc.org/sqlite"
)

var tempDirectories = []string{"/tmp", "/.ecr"}

const (
	registrySource = "registry"
)

func GenerateImageSBOM(ctx context.Context, image string, keychain authn.Keychain) (encodedSBOM []byte, err error) {
	defer func() {
		if cleanupErr := cleanupDirectories(tempDirectories); cleanupErr != nil {
			err = multierror.Append(err, cleanupErr)
		}
	}()

	src, err := syft.GetSource(ctx, image, syft.DefaultGetSourceConfig().WithRegistryOptions(&stereoscopeImage.RegistryOptions{Keychain: keychain}).WithSources(registrySource))
	if err != nil {
		return nil, err
	}

	sbom, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, err
	}

	if sbom == nil {
		return nil, fmt.Errorf("invalid sbom value")
	}

	encodedSBOM, err = format.Encode(*sbom, syftjson.NewFormatEncoder())
	if err != nil {
		return nil, err
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
		return err
	}

	defer func() {
		if err := d.Close(); err != nil {
			err = fmt.Errorf("error cleaning up temp dir: %w", err)
		}
	}()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}

	for _, name := range names {
		err = os.RemoveAll(filepath.Join(directory, name))
		if err != nil {
			return err
		}
	}

	return nil
}

package sbom

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadConfigFrom(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syft.yaml")
	if err := os.WriteFile(path, []byte("from:\n  - containerd\nselect-catalogers:\n  - '+javascript-lock-cataloger'\njavascript:\n  include-dev-dependencies: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := readCreateSBOMConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CreateSBOMConfig == nil || !reflect.DeepEqual(cfg.From, []string{"containerd"}) {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

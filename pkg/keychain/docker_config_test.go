package keychain

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
)

func TestCreateMountedSecretKeychainFromFile_DockerConfigJSONMatchesRegistryPath(t *testing.T) {
	username, password := "foo", "bar"
	config := []byte(`{"auths":{"https://index.docker.io/v1/":{"username":"` + username + `","password":"` + password + `","auth":"` + base64.StdEncoding.EncodeToString([]byte(username+":"+password)) + `"}}}`)

	path := filepath.Join(t.TempDir(), ".dockerconfigjson")
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}

	kc, ok := createMountedSecretKeychainFromFile(context.Background(), path, corev1.SecretTypeDockerConfigJson, corev1.DockerConfigJsonKey)
	if !ok {
		t.Fatal("createMountedSecretKeychainFromFile() did not load mounted docker config")
	}

	repo, err := name.NewRepository("index.docker.io/library/busybox", name.WeakValidation)
	if err != nil {
		t.Fatalf("NewRepository() = %v", err)
	}

	authenticator, err := kc.Resolve(repo)
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}

	got, err := authenticator.Authorization()
	if err != nil {
		t.Fatalf("Authorization() = %v", err)
	}

	want, err := (&authn.Basic{Username: username, Password: password}).Authorization()
	if err != nil {
		t.Fatalf("Basic.Authorization() = %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Authorization() = %#v, want %#v", got, want)
	}
}

func TestCreateMountedSecretKeychainFromFile_DockercfgMatchesRegistry(t *testing.T) {
	username, password := "legacy-user", "legacy-password"
	config := []byte(`{"quay.io":{"auth":"` + base64.StdEncoding.EncodeToString([]byte(username+":"+password)) + `"}}`)

	path := filepath.Join(t.TempDir(), ".dockercfg")
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatalf("WriteFile() = %v", err)
	}

	kc, ok := createMountedSecretKeychainFromFile(context.Background(), path, corev1.SecretTypeDockercfg, corev1.DockerConfigKey)
	if !ok {
		t.Fatal("createMountedSecretKeychainFromFile() did not load mounted dockercfg")
	}

	repo, err := name.NewRepository("quay.io/example/private-image", name.WeakValidation)
	if err != nil {
		t.Fatalf("NewRepository() = %v", err)
	}

	authenticator, err := kc.Resolve(repo)
	if err != nil {
		t.Fatalf("Resolve() = %v", err)
	}

	got, err := authenticator.Authorization()
	if err != nil {
		t.Fatalf("Authorization() = %v", err)
	}

	want, err := (&authn.Basic{Username: username, Password: password}).Authorization()
	if err != nil {
		t.Fatalf("Basic.Authorization() = %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Authorization() = %#v, want %#v", got, want)
	}
}

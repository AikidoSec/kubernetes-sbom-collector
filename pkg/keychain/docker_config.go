package keychain

import (
	"context"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	k8sauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	corev1 "k8s.io/api/core/v1"
)

const (
	// MountedDockerConfigPath is the default path where Docker config secrets can be mounted.
	// Customers can mount their registry credentials as a secret to this location.
	// This supports any registry including OpenShift's internal registry, Red Hat registries,
	// and other private registries.
	MountedDockerConfigPath = "/var/run/secrets/pull-secret/.dockerconfigjson"

	// MountedDockerLegacyConfigPath supports legacy dockercfg-style pull secrets.
	MountedDockerLegacyConfigPath = "/var/run/secrets/pull-secret/.dockercfg"
)

// CreateMountedSecretKeychain creates a keychain that uses a mounted Docker config secret.
// This supports authentication with any container registry by reading either standard Docker
// config.json format from a secret mounted at MountedDockerConfigPath or legacy .dockercfg
// format from a secret mounted at MountedDockerLegacyConfigPath.
func CreateMountedSecretKeychain(ctx context.Context) authn.Keychain {
	mountedSecrets := []struct {
		path       string
		secretType corev1.SecretType
		secretKey  string
	}{
		{
			path:       MountedDockerConfigPath,
			secretType: corev1.SecretTypeDockerConfigJson,
			secretKey:  corev1.DockerConfigJsonKey,
		},
		{
			path:       MountedDockerLegacyConfigPath,
			secretType: corev1.SecretTypeDockercfg,
			secretKey:  corev1.DockerConfigKey,
		},
	}

	for _, mountedSecret := range mountedSecrets {
		keychain, ok := createMountedSecretKeychainFromFile(ctx, mountedSecret.path, mountedSecret.secretType, mountedSecret.secretKey)
		if ok {
			return keychain
		}
	}

	// No secret mounted, return a no-op keychain
	return authn.NewMultiKeychain()
}

func createMountedSecretKeychainFromFile(ctx context.Context, path string, secretType corev1.SecretType, secretKey string) (authn.Keychain, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	keychain, err := k8sauth.NewFromPullSecrets(ctx, []corev1.Secret{normalizeSecret(corev1.Secret{
		Type: secretType,
		Data: map[string][]byte{
			secretKey: data,
		},
	})})
	if err != nil {
		return nil, false
	}

	return keychain, true
}

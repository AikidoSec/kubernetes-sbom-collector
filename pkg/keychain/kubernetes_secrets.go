package keychain

import (
	"context"
	"encoding/json"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const defaultServiceAccount = "default"

type dockerConfigJSON struct {
	Auths map[string]authn.AuthConfig `json:"auths"`
}

// CreateKeychainFromPullSecrets resolves the given secret names in a namespace, normalizes
// registry aliases when needed, and constructs a registry keychain from them.
func CreateKeychainFromPullSecrets(ctx context.Context, client kubernetes.Interface, namespace string, secretNames []string) (authn.Keychain, error) {
	pullSecrets := make([]corev1.Secret, 0, len(secretNames))
	for _, name := range secretNames {
		ps, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}

		pullSecrets = append(pullSecrets, normalizeSecret(*ps))
	}

	return k8schain.NewFromPullSecrets(ctx, pullSecrets)
}

// GetServiceAccountSecretNames returns imagePullSecrets attached to the given service account.
// Generic service account secrets can include tokens and are not registry credentials.
func GetServiceAccountSecretNames(ctx context.Context, client kubernetes.Interface, namespace, serviceAccountName string) ([]string, error) {
	if serviceAccountName == "" {
		serviceAccountName = defaultServiceAccount
	}

	sa, err := client.CoreV1().ServiceAccounts(namespace).Get(ctx, serviceAccountName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(sa.ImagePullSecrets))
	for _, secret := range sa.ImagePullSecrets {
		names = append(names, secret.Name)
	}

	return names, nil
}

func normalizeSecret(secret corev1.Secret) corev1.Secret {
	switch secret.Type {
	case corev1.SecretTypeDockerConfigJson:
		if data, ok := secret.Data[corev1.DockerConfigJsonKey]; ok && len(data) > 0 {
			secret.Data[corev1.DockerConfigJsonKey] = normalizeDockerConfigJSON(data)
		}
	case corev1.SecretTypeDockercfg:
		if data, ok := secret.Data[corev1.DockerConfigKey]; ok && len(data) > 0 {
			secret.Data[corev1.DockerConfigKey] = normalizeDockercfg(data)
		}
	}

	return secret
}

func normalizeDockerConfigJSON(data []byte) []byte {
	var cfg dockerConfigJSON
	if err := json.Unmarshal(data, &cfg); err != nil || len(cfg.Auths) == 0 {
		return data
	}

	addDockerHubAliases(cfg.Auths)

	normalized, err := json.Marshal(cfg)
	if err != nil {
		return data
	}

	return normalized
}

func normalizeDockercfg(data []byte) []byte {
	var auths map[string]authn.AuthConfig
	if err := json.Unmarshal(data, &auths); err != nil || len(auths) == 0 {
		return data
	}

	addDockerHubAliases(auths)

	normalized, err := json.Marshal(auths)
	if err != nil {
		return data
	}

	return normalized
}

func addDockerHubAliases(auths map[string]authn.AuthConfig) {
	aliases := []string{
		"docker.io",
		"index.docker.io",
		"https://index.docker.io/v1/",
	}

	for _, source := range aliases {
		auth, ok := auths[source]
		if !ok {
			continue
		}

		for _, target := range aliases {
			if _, exists := auths[target]; !exists {
				auths[target] = auth
			}
		}

		return
	}
}

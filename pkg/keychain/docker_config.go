package keychain

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
)

const (
	// MountedDockerConfigPath is the default path where Docker config secrets can be mounted.
	// Customers can mount their registry credentials as a secret to this location.
	// This supports any registry including OpenShift's internal registry, Red Hat registries,
	// and other private registries.
	MountedDockerConfigPath = "/var/run/secrets/pull-secret/.dockerconfigjson"
)

// CreateMountedSecretKeychain creates a keychain that uses a mounted Docker config secret.
// This supports authentication with any container registry by reading standard Docker config
// format from a mounted secret. The secret should be mounted at MountedDockerConfigPath.
func CreateMountedSecretKeychain() authn.Keychain {
	// Check if a Docker config secret is mounted
	if _, err := os.Stat(MountedDockerConfigPath); err == nil {
		// Read and parse the Docker config from the mounted secret
		data, err := os.ReadFile(MountedDockerConfigPath)
		if err == nil {
			var configFile dockerConfigFile
			if err := json.Unmarshal(data, &configFile); err == nil {
				return authn.NewKeychainFromHelper(dockerConfigKeychain{auths: configFile.Auths})
			}
		}
	}

	// No secret mounted, return a no-op keychain
	return authn.NewMultiKeychain()
}

// dockerConfigFile represents the structure of a Docker config.json file
type dockerConfigFile struct {
	Auths map[string]dockerAuthConfig `json:"auths"`
}

// dockerAuthConfig represents authentication configuration for a registry
type dockerAuthConfig struct {
	Auth     string `json:"auth,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// dockerConfigKeychain implements authn.Helper to provide authentication from a Docker config
type dockerConfigKeychain struct {
	auths map[string]dockerAuthConfig
}

// Get implements authn.Helper.Get
func (d dockerConfigKeychain) Get(serverURL string) (string, string, error) {
	// Try exact match first
	if auth, exists := d.auths[serverURL]; exists {
		return extractCredentials(auth)
	}

	// Normalize the URL - try both with and without https:// prefix
	// Docker config files may store registry URLs with or without the scheme
	var alternativeURL string
	if strings.HasPrefix(serverURL, "https://") {
		// If URL has https://, try without it
		alternativeURL = strings.TrimPrefix(serverURL, "https://")
	} else {
		// If URL doesn't have https://, try with it
		alternativeURL = "https://" + serverURL
	}

	if auth, exists := d.auths[alternativeURL]; exists {
		return extractCredentials(auth)
	}

	return "", "", nil
}

// extractCredentials extracts username and password from dockerAuthConfig
func extractCredentials(auth dockerAuthConfig) (string, string, error) {
	// If username and password are set directly, use them
	if auth.Username != "" || auth.Password != "" {
		return auth.Username, auth.Password, nil
	}

	// If auth field is set (base64 encoded username:password), decode it
	if auth.Auth != "" {
		decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
		if err != nil {
			return "", "", err
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) == 2 {
			return parts[0], parts[1], nil
		}
	}

	return "", "", nil
}

package output

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"aikidoSec.kubernetes-sbom-collector/pkg/models"
)

type Client struct {
	clusterIdentifier            string
	sharedTokenEnabled           string
	sharedTokenClusterIdentifier string
	client                       *http.Client
	logger                       *slog.Logger
	host                         string
}

func NewClient(logger *slog.Logger, host, clusterIdentifier string, sharedToken models.SharedTokenConfig) (*Client, error) {
	sharedTokenEnabled := "false"
	if sharedToken.Enabled {
		sharedTokenEnabled = "true"
	}
	c := http.DefaultClient
	client := &Client{clusterIdentifier: clusterIdentifier, sharedTokenEnabled: sharedTokenEnabled, sharedTokenClusterIdentifier: sharedToken.ClusterIdentifier, client: c, host: host, logger: logger}

	if err := client.validateHost(); err != nil {
		return nil, err
	}

	return client, nil
}

func (c *Client) validateHost() error {
	u, err := url.Parse(c.host)
	if err != nil {
		return fmt.Errorf("invalid host URL: %w", err)
	}

	// Only allow HTTP and HTTPS
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("invalid scheme: %s", u.Scheme)
	}

	return nil
}

func (c *Client) SendSBOM(ctx context.Context, payload []byte, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/sbom", c.host), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Set("X-Cluster-Identifier", c.clusterIdentifier)
	req.Header.Set("X-Shared-Token-Enabled", c.sharedTokenEnabled)
	req.Header.Set("X-Shared-Token-Cluster-Identifier", c.sharedTokenClusterIdentifier)
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("could not send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			c.logger.Warn("error closing response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			c.logger.Warn("error reading response body", "error", err)
		}

		return fmt.Errorf("error sending request to server: %s: %s", resp.Status, string(respBody))
	}

	return nil
}

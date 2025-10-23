package output

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"aikidoSec.kubernetes-sbom-collector/pkg/models"
)

type Client struct {
	client     *http.Client
	logger     *slog.Logger
	host       string
	retryDelay time.Duration
}

func NewClient(logger *slog.Logger, host string, retryDelay time.Duration) *Client {
	c := http.DefaultClient
	return &Client{client: c, host: host, logger: logger, retryDelay: retryDelay}
}

func (c *Client) SendSBOM(ctx context.Context, sbomPayload models.SBOMPayload, token string) error {
	payload, err := json.Marshal(sbomPayload)
	if err != nil {
		return fmt.Errorf("could not marshal SBOM payload: %w", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(payload); err != nil {
		return fmt.Errorf("could not gzip SBOM payload: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("could not gzip SBOM payload: %w", err)
	}

	r := bytes.NewReader(buf.Bytes())
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/sbom", c.host), r)
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)
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
		c.logger.Warn("received unexpected status code", "status", resp.Status)
		time.Sleep(c.retryDelay)
		return c.SendSBOM(ctx, sbomPayload, token)
	}

	return nil
}

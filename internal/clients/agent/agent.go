package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"aikidoSec.kubernetes-sbom-collector/pkg/models"
)

type Client struct {
	client     *http.Client
	logger     *slog.Logger
	host       string
	retryDelay time.Duration
}

func NewClient(logger *slog.Logger, host string, retryDelay time.Duration) (*Client, error) {
	c := http.DefaultClient
	client := &Client{client: c, host: host, logger: logger, retryDelay: retryDelay}

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

func (c *Client) GetCollectorConfig(ctx context.Context) (models.CollectorConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/sbom-collector/config", c.host), nil)
	if err != nil {
		return models.CollectorConfig{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	res, err := c.client.Do(req)
	if err != nil {
		c.logger.Warn("error making request to get collector config", "error", err)
		// Kubernetes agent might take some time to be ready, so we retry on error
		time.Sleep(c.retryDelay)
		return c.GetCollectorConfig(ctx)
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			c.logger.Warn("error closing response body", "error", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		c.logger.Warn("unexpected status code", "status_code", res.StatusCode)
		time.Sleep(c.retryDelay)
		return c.GetCollectorConfig(ctx)
	}

	var response models.CollectorConfig
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return models.CollectorConfig{}, err
	}

	return response, nil
}

func (c *Client) GetAPIToken(ctx context.Context) (models.APIToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/sbom-collector/token", c.host), nil)
	if err != nil {
		return models.APIToken{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	res, err := c.client.Do(req)
	if err != nil {
		return models.APIToken{}, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			c.logger.Warn("error closing response body", "error", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		c.logger.Warn("unexpected status code", "status_code", res.StatusCode)
		time.Sleep(c.retryDelay)
		return c.GetAPIToken(ctx)
	}

	var response models.APIToken
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return models.APIToken{}, err
	}

	return response, nil
}

func (c *Client) GetImageStatus(ctx context.Context, image, digest string) (models.ImageStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/sbom-collector/image-status?image=%s&digest=%s", c.host, url.QueryEscape(image), url.QueryEscape(digest)), nil)
	if err != nil {
		return models.ImageStatus{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	res, err := c.client.Do(req)
	if err != nil {
		return models.ImageStatus{}, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			c.logger.Warn("error closing response body", "error", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		c.logger.Warn("unexpected status code", "status_code", res.StatusCode)
		time.Sleep(c.retryDelay)
		return c.GetImageStatus(ctx, image, digest)
	}

	var response models.ImageStatus
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return models.ImageStatus{}, err
	}

	return response, nil
}

func (c *Client) SetImageStatus(ctx context.Context, status models.ImageStatus) error {
	payload, err := json.Marshal(status)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/sbom-collector/image-status", c.host), bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			c.logger.Warn("error closing response body", "error", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		c.logger.Warn("unexpected status code", "status_code", res.StatusCode)
		time.Sleep(c.retryDelay)
		return c.SetImageStatus(ctx, status)
	}

	return nil
}

package logger

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"aikidoSec.kubernetes-sbom-collector/pkg/models"
)

type Logger struct {
	logger              *slog.Logger
	client              *http.Client
	apiToken            string
	host                string
	errorLogsSuppressed bool
	nodeName            string
}

func NewLogger(logger *slog.Logger, host string, errorLogsSuppressed bool, nodeName string) *Logger {
	return &Logger{
		logger:              logger,
		client:              http.DefaultClient,
		host:                host,
		errorLogsSuppressed: errorLogsSuppressed,
		nodeName:            nodeName,
	}
}

func (s *Logger) ReportError(ctx context.Context, err error, message string, errorType string, args ...any) {
	if err == nil {
		return
	}

	// These errors might be caused by the automatic update process stopping the agent
	if strings.Contains(err.Error(), "context canceled") {
		return
	}

	if !s.errorLogsSuppressed {
		s.logger.Error(fmt.Sprintf("%s: %s", message, err.Error()), args...)
	}

	reportedError := make(map[string]any)
	reportedError["message"] = message
	reportedError["error"] = err.Error()
	reportedError["nodeName"] = s.nodeName
	for i := 0; i < len(args)-1; i += 2 {
		reportedError[fmt.Sprintf("%v", args[i])] = args[i+1]
	}

	if err := s.sendError(ctx, models.AgentError{
		Error:     reportedError,
		ErrorType: errorType,
		SeenAt:    time.Now().UTC(),
	}); err != nil {
		s.logger.Error(fmt.Sprintf("error sending agent errors: %s", err.Error()), args...)
	}
}

func (s *Logger) LogError(err error, message string, args ...any) {
	if err == nil {
		return
	}

	if s.errorLogsSuppressed {
		return
	}

	s.logger.Error(fmt.Sprintf("%s: %s", message, err.Error()), args...)
}

func (s *Logger) LogInfo(message string, args ...any) {
	s.logger.Info(message, args...)
}

func (s *Logger) LogWarning(err error, message string, args ...any) {
	if err == nil {
		return
	}

	s.logger.Warn(fmt.Sprintf("%s: %s", message, err.Error()), args...)
}

func (s *Logger) GetLogger() *slog.Logger {
	return s.logger
}

func (s *Logger) Close() {
	s.client.CloseIdleConnections()
}

func (s *Logger) SetAPIToken(token string) {
	s.apiToken = token
}

func (s *Logger) sendError(ctx context.Context, agentError models.AgentError) error {
	payload, err := json.Marshal(agentError)
	if err != nil {
		return fmt.Errorf("could not marshal error payload: %w", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(payload); err != nil {
		return fmt.Errorf("could not gzip error payload: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("could not gzip error payload: %w", err)
	}

	r := bytes.NewReader(buf.Bytes())
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/sbom-collector/errors", s.host), r)
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.apiToken)
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("could not send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Error("error closing response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		s.logger.Warn("received unexpected status code when sending error", "code", resp.StatusCode)
		time.Sleep(time.Second * 15)
		return s.sendError(ctx, agentError)
	}

	return nil
}

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
	logger   *slog.Logger
	client   *http.Client
	apiToken string
	host     string
}

func NewLogger(logger *slog.Logger, host string) *Logger {
	return &Logger{
		logger: logger,
		client: http.DefaultClient,
		host:   host,
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

	s.logger.Error(fmt.Sprintf("%s: %s", message, err.Error()), args...)

	// Build error message as JSON
	builder := strings.Builder{}
	builder.WriteString("{\"message\":")
	errJSON, err := json.Marshal(err.Error())
	if err != nil {
		builder.WriteString(fmt.Sprintf(`"%v"`, err.Error()))
	} else {
		builder.WriteString(string(errJSON))
	}

	for i := 0; i < len(args)-1; i += 2 {
		if i+1 >= len(args) {
			break
		}

		key, ok := args[i].(string)
		if !ok {
			continue
		}
		builder.WriteString(",\"")
		builder.WriteString(key)
		builder.WriteString("\":")

		argValue, err := json.Marshal(args[i+1])
		if err != nil {
			builder.WriteString(fmt.Sprintf(`"%v"`, args[i+1]))
			continue
		}
		builder.WriteString(string(argValue))
	}
	builder.WriteString("}")
	errorMessage := builder.String()

	if err := s.sendError(ctx, models.AgentError{
		Error:     errorMessage,
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

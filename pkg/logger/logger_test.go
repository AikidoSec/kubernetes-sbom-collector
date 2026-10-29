package logger

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"aikidoSec.kubernetes-sbom-collector/internal/clients/agent"
	"aikidoSec.kubernetes-sbom-collector/pkg/models"
)

func TestSendErrorIncludesSharedTokenHeaders(t *testing.T) {
	operator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sbom-collector/token" {
			t.Errorf("unexpected agent request: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"token":"rotated-token"}`))
	}))
	defer operator.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer rotated-token" || r.Header.Get("X-Shared-Token-Enabled") != "true" || r.Header.Get("X-Shared-Token-Cluster-Identifier") != "production" {
			t.Error("missing current token or shared cluster routing headers")
		}
		if r.Header.Get("X-Cluster-Identifier") != "cluster-uid" {
			t.Error("missing cluster identifier header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	agentClient, err := agent.NewClient(slog.Default(), operator.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	logger := NewLogger(slog.Default(), server.URL, "cluster-uid", models.SharedTokenConfig{Enabled: true, ClusterIdentifier: "production"}, false, "node", agentClient)
	if err := logger.sendError(context.Background(), []models.AgentError{}); err != nil {
		t.Fatal(err)
	}
}

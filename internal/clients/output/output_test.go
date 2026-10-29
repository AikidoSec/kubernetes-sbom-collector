package output

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"aikidoSec.kubernetes-sbom-collector/pkg/models"
)

func TestSendSBOMIncludesSharedTokenHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("X-Shared-Token-Enabled") != "true" || r.Header.Get("X-Shared-Token-Cluster-Identifier") != "production" {
			t.Error("missing token or shared cluster routing headers")
		}
		if r.Header.Get("X-Cluster-Identifier") != "cluster-uid" {
			t.Error("missing cluster identifier header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(slog.Default(), server.URL, "cluster-uid", models.SharedTokenConfig{Enabled: true, ClusterIdentifier: "production"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendSBOM(context.Background(), models.SBOMPayload{}, "token"); err != nil {
		t.Fatal(err)
	}
}

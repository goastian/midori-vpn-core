package tunnel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/proxytoken"
)

func TestWSGatewayRejectsMissingOrWrongServerCredential(t *testing.T) {
	serverID := uuid.New()
	gateway := NewWSGateway(51820, "test-secret", serverID, 1)

	missing := httptest.NewRequest(http.MethodGet, "/api/v1/tunnel/ws", nil)
	missingRecorder := httptest.NewRecorder()
	gateway.Handler(missingRecorder, missing)
	if missingRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing credential status = %d, want %d", missingRecorder.Code, http.StatusUnauthorized)
	}

	wrongServer := proxytoken.GenerateTunnel(proxytoken.TunnelClaims{UserID: uuid.New(), DeviceID: uuid.New(), ServerID: uuid.New()}, "test-secret", time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnel/ws", nil)
	req.Header.Set("Authorization", "Bearer "+wrongServer)
	recorder := httptest.NewRecorder()
	gateway.Handler(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong server credential status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

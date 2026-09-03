package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/proxytoken"
)

func TestWSGatewayRejectsMissingOrWrongServerCredential(t *testing.T) {
	serverID := uuid.New()
	clusterID := uuid.New()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := proxytoken.NewSigner("control", "https://control.test", base64.RawURLEncoding.EncodeToString(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := proxytoken.NewVerifier("https://control.test", "control="+base64.RawURLEncoding.EncodeToString(publicKey), false, "")
	if err != nil {
		t.Fatal(err)
	}
	gateway := NewWSGateway(51820, verifier, serverID, clusterID, 1)

	missing := httptest.NewRequest(http.MethodGet, "/api/v1/tunnel/ws", nil)
	missingRecorder := httptest.NewRecorder()
	gateway.Handler(missingRecorder, missing)
	if missingRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing credential status = %d, want %d", missingRecorder.Code, http.StatusUnauthorized)
	}
	var missingEnvelope struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(missingRecorder.Body.Bytes(), &missingEnvelope); err != nil {
		t.Fatalf("decode missing credential response: %v", err)
	}
	if missingEnvelope.Code != "unauthorized" {
		t.Fatalf("missing credential code = %q, want unauthorized", missingEnvelope.Code)
	}

	wrongServer, err := signer.Issue(proxytoken.AudienceVPNTunnel, uuid.New(), uuid.New(), uuid.New(), clusterID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tunnel/ws", nil)
	req.Header.Set("Authorization", "Bearer "+wrongServer)
	recorder := httptest.NewRecorder()
	gateway.Handler(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong server credential status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}

	wrongCluster, err := signer.Issue(proxytoken.AudienceVPNTunnel, uuid.New(), uuid.New(), serverID, uuid.New(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clusterRequest := httptest.NewRequest(http.MethodGet, "/api/v1/tunnel/ws", nil)
	clusterRequest.Header.Set("Authorization", "Bearer "+wrongCluster)
	clusterRecorder := httptest.NewRecorder()
	gateway.Handler(clusterRecorder, clusterRequest)
	if clusterRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong cluster credential status = %d, want %d", clusterRecorder.Code, http.StatusUnauthorized)
	}
}

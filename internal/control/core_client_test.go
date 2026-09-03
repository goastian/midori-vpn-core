package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/nodeauth"
	"github.com/google/uuid"
)

func useTestCoreServer(t *testing.T, handler http.Handler) (*models.VPNServer, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	previousClient := coreHTTP
	previousAllowInsecureHTTP := coreAllowInsecureHTTP
	previousAllowedHosts := coreAllowedHosts
	previousSigner := coreSigner

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	if err := InitCoreSigningIdentity("control-contract-test", base64.RawURLEncoding.EncodeToString(privateKey)); err != nil {
		server.Close()
		t.Fatal(err)
	}
	InitCoreClient(false, true, "")
	coreHTTP = server.Client()

	cleanup := func() {
		server.Close()
		coreHTTP = previousClient
		coreAllowInsecureHTTP = previousAllowInsecureHTTP
		coreAllowedHosts = previousAllowedHosts
		coreSigner = previousSigner
	}
	return &models.VPNServer{Host: server.URL, Port: 1}, cleanup
}

func TestCoreURLAllowedHostsAcceptsOrigins(t *testing.T) {
	InitCoreClient(false, false, "https://vpn.astian.org,https://de.vpn.astian.org")

	got, _, err := coreURL(&models.VPNServer{
		Host: "de.vpn.astian.org",
		Port: 8080,
	}, "/api/v1/peers")
	if err != nil {
		t.Fatalf("coreURL() error = %v", err)
	}
	if !strings.HasPrefix(got, "https://de.vpn.astian.org:8080/api/v1/peers") {
		t.Fatalf("coreURL() = %q", got)
	}
}

func TestCoreDoWithRetrySignsRequest(t *testing.T) {
	previousSigner := coreSigner
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoding := base64.RawURLEncoding
	if err := InitCoreSigningIdentity("control-test", encoding.EncodeToString(privateKey)); err != nil {
		t.Fatal(err)
	}
	verifier, err := nodeauth.NewVerifier("control-test="+encoding.EncodeToString(publicKey), "", "")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"public_key":"test"}`)
	server := httptest.NewServer(verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if string(got) != string(body) {
			t.Errorf("body = %q, want %q", got, body)
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	defer server.Close()

	previousClient := coreHTTP
	coreHTTP = server.Client()
	t.Cleanup(func() {
		coreHTTP = previousClient
		coreSigner = previousSigner
	})
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/peers", nil)
	resp, err := coreDoWithRetry(req, body, "signed-test")
	if err != nil {
		t.Fatalf("signed request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestCoreURLAllowedHostsRejectsUnknownHost(t *testing.T) {
	InitCoreClient(false, false, "vpn.astian.org,de.vpn.astian.org")

	_, _, err := coreURL(&models.VPNServer{
		Host: "evil.example",
		Port: 8080,
	}, "/api/v1/peers")
	if err == nil {
		t.Fatal("coreURL() error = nil, want rejection")
	}
	if !strings.Contains(err.Error(), "not in allowed hosts whitelist") {
		t.Fatalf("coreURL() error = %q", err)
	}
}

func TestNormalizeCoreAllowedHost(t *testing.T) {
	tests := map[string]string{
		"de.vpn.astian.org":             "de.vpn.astian.org",
		"DE.VPN.ASTIAN.ORG":             "de.vpn.astian.org",
		"https://de.vpn.astian.org":     "de.vpn.astian.org",
		"https://de.vpn.astian.org:443": "de.vpn.astian.org",
		"de.vpn.astian.org:8085":        "de.vpn.astian.org",
	}

	for input, want := range tests {
		if got := normalizeCoreAllowedHost(input); got != want {
			t.Fatalf("normalizeCoreAllowedHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCallCoreAddPeerCarriesAndVerifiesOperationID(t *testing.T) {
	operationID := uuid.NewString()
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	server, cleanup := useTestCoreServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/peers" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			PublicKey   string `json:"public_key"`
			OperationID string `json:"operation_id"`
			Keepalive   int    `json:"keepalive"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.PublicKey != publicKey || body.OperationID != operationID || body.Keepalive != 25 {
			t.Errorf("unexpected request body: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"data": map[string]any{
				"public_key": publicKey, "operation_id": operationID,
				"allowed_ip": "10.8.0.2/32", "endpoint": "vpn.test:51820",
			},
		})
	}))
	defer cleanup()

	response, err := CallCoreAddPeer(server, publicKey, operationID)
	if err != nil {
		t.Fatal(err)
	}
	if response.OperationID != operationID || response.AllowedIP != "10.8.0.2/32" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestCallCoreRemoveCurrentPeerUsesObservedOperation(t *testing.T) {
	operationID := uuid.NewString()
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	var deleteCount int
	server, cleanup := useTestCoreServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":   true,
				"data": map[string]any{"public_key": publicKey, "operation_id": operationID},
			})
		case http.MethodDelete:
			deleteCount++
			if got := r.URL.Query().Get("expected_operation_id"); got != operationID {
				t.Errorf("expected_operation_id = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": map[string]string{"removed": publicKey}})
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer cleanup()

	if err := CallCoreRemoveCurrentPeer(server, publicKey); err != nil {
		t.Fatal(err)
	}
	if deleteCount != 1 {
		t.Fatalf("delete count = %d", deleteCount)
	}
}

func TestCoreConflictRemainsTyped(t *testing.T) {
	server, cleanup := useTestCoreServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "code": "peer_operation_conflict", "error": "peer is owned by another operation",
		})
	}))
	defer cleanup()

	err := CallCoreRemovePeer(server, base64.StdEncoding.EncodeToString(make([]byte, 32)), uuid.NewString())
	var coreError *CoreAPIError
	if !errors.As(err, &coreError) || coreError.Status != http.StatusConflict || coreError.Code != "peer_operation_conflict" {
		t.Fatalf("error = %#v", err)
	}
}

package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/nodeauth"
)

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

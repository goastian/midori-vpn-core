package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRealIPRejectsForwardedHeadersFromUntrustedPeer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.9:4321"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	req.Header.Set("X-Real-IP", "1.1.1.1")

	if got := RealIP(req, ParseTrustedProxies("127.0.0.1/32")); got != "198.51.100.9" {
		t.Fatalf("RealIP() = %q, want direct peer address", got)
	}
}

func TestRealIPUsesRightmostUntrustedForwardedAddress(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 198.51.100.10")

	trusted := ParseTrustedProxies("127.0.0.1/32,198.51.100.0/24")
	if got := RealIP(req, trusted); got != "8.8.8.8" {
		t.Fatalf("RealIP() = %q, want original untrusted address", got)
	}
}

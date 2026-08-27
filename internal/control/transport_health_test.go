package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/goastian/midori-vpn-core/internal/models"
)

func TestProbeTransportKeepsUnverifiableProtocolsUnknown(t *testing.T) {
	for _, protocol := range []string{"openvpn", "ikev2"} {
		status, checked := probeTransport(context.Background(), &models.VPNServer{}, models.TransportCapability{Protocol: protocol})
		if checked || status != "unknown" {
			t.Fatalf("unverifiable protocol %s result = %q, %t", protocol, status, checked)
		}
	}
}

func TestProbeOpenVPNRequiresLoopbackDCOHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"dco":true}`))
	}))
	defer server.Close()
	transport := models.TransportCapability{Protocol: "openvpn", Metadata: map[string]interface{}{"health_url": server.URL + "/healthz"}}
	status, checked := probeTransport(context.Background(), &models.VPNServer{}, transport)
	if !checked || status != "healthy" {
		t.Fatalf("OpenVPN probe result = %q, %t", status, checked)
	}

	transport.Metadata["health_url"] = "http://example.test:9194/healthz"
	if status, checked := probeTransport(context.Background(), &models.VPNServer{}, transport); checked || status != "unknown" {
		t.Fatalf("external health URL result = %q, %t", status, checked)
	}
}

func TestProbeIKEv2RequiresFreshPrivateVICIHealth(t *testing.T) {
	privateFile := "/run/midorivpn-health/ikev2.json"
	transport := models.TransportCapability{Protocol: "ikev2", Metadata: map[string]interface{}{"health_file": privateFile}}
	healthy, checked := probeIKEv2Status(transport, time.Now(), func(path string, _ time.Time) error {
		if path != privateFile {
			t.Fatalf("status path = %q", path)
		}
		return nil
	})
	if !healthy || !checked {
		t.Fatalf("IKEv2 probe result = %t, %t", healthy, checked)
	}
	transport.Metadata["health_file"] = "/tmp/attacker.json"
	if _, checked := probeIKEv2Status(transport, time.Now(), func(string, time.Time) error { return nil }); checked {
		t.Fatal("external IKEv2 health file was accepted")
	}
}

func TestProbeWSSRequiresAuthenticationResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tunnel/ws" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "authentication required", http.StatusUnauthorized)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	previousClient := coreHTTP
	coreHTTP = server.Client()
	t.Cleanup(func() { coreHTTP = previousClient })

	transport := models.TransportCapability{Protocol: "wss", Host: parsed.Hostname(), Port: port, Enabled: true}
	status, checked := probeTransport(context.Background(), &models.VPNServer{}, transport)
	if !checked || status != "healthy" {
		t.Fatalf("WSS probe result = %q, %t", status, checked)
	}
}

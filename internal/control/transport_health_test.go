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

func TestProbeOpenVPNPrefersFreshPrivateHealthFile(t *testing.T) {
	privateFile := "/run/midorivpn-health/openvpn.json"
	transport := models.TransportCapability{Protocol: "openvpn", Metadata: map[string]interface{}{"health_file": privateFile}}
	healthy, checked := probeOpenVPNStatus(transport, time.Now(), func(path string, _ time.Time) error {
		if path != privateFile {
			t.Fatalf("status path = %q", path)
		}
		return nil
	})
	if !healthy || !checked {
		t.Fatalf("OpenVPN file probe result = %t, %t", healthy, checked)
	}
	transport.Metadata["health_file"] = "/tmp/attacker.json"
	if _, checked := probeOpenVPNStatus(transport, time.Now(), func(string, time.Time) error { return nil }); checked {
		t.Fatal("external OpenVPN health file was accepted")
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

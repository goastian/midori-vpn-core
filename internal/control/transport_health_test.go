package control

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

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

func TestProbeIKEv2RequiresLoopbackVICIHealth(t *testing.T) {
	directory := t.TempDir()
	socket := filepath.Join(directory, "health.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"ikev2":true}`))
	})}
	go server.Serve(listener)
	defer server.Close()
	privateSocket := "/run/midorivpn-health/ikev2.sock"
	if err := os.MkdirAll(filepath.Dir(privateSocket), 0o700); err != nil {
		t.Skipf("private runtime path unavailable: %v", err)
	}
	if err := os.Symlink(socket, privateSocket); err != nil {
		t.Skipf("private health socket unavailable: %v", err)
	}
	defer os.Remove(privateSocket)
	transport := models.TransportCapability{Protocol: "ikev2", Metadata: map[string]interface{}{"health_socket": privateSocket}}
	status, checked := probeTransport(context.Background(), &models.VPNServer{}, transport)
	if status != "healthy" || !checked {
		t.Fatalf("IKEv2 probe result = %q, %t", status, checked)
	}
	transport.Metadata["health_socket"] = "/tmp/attacker.sock"
	if _, checked := probeTransport(context.Background(), &models.VPNServer{}, transport); checked {
		t.Fatal("external IKEv2 health URL was accepted")
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

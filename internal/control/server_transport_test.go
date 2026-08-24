package control

import (
	"testing"

	"github.com/goastian/midori-vpn-core/internal/models"
)

func boolPtr(value bool) *bool { return &value }

func TestValidateTransportRequests(t *testing.T) {
	valid := []TransportRequest{{
		Protocol: "WSS", Host: "https://relay.example.org:8443", Port: 443,
		Enabled: boolPtr(true), Priority: 90, Metadata: map[string]interface{}{"path": "/vpn"},
	}}
	transports, err := validateTransportRequests(valid, true, false)
	if err != nil {
		t.Fatalf("valid transport rejected: %v", err)
	}
	if len(transports) != 1 || transports[0].Protocol != "wss" || transports[0].Host != "relay.example.org" || transports[0].Port != 8443 {
		t.Fatalf("transport normalization mismatch: %#v", transports)
	}
	if transports[0].HealthStatus != "unknown" || !transports[0].Enabled {
		t.Fatalf("unexpected initial transport state: %#v", transports[0])
	}
}

func TestValidateTransportRequestsRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name  string
		items []TransportRequest
	}{
		{"empty", nil},
		{"duplicate protocol", []TransportRequest{
			{Protocol: "wireguard", Host: "vpn.example.org", Port: 51820, Enabled: boolPtr(true)},
			{Protocol: "wireguard", Host: "vpn2.example.org", Port: 51820, Enabled: boolPtr(true)},
		}},
		{"unknown protocol", []TransportRequest{{Protocol: "ssh", Host: "vpn.example.org", Port: 22, Enabled: boolPtr(true)}}},
		{"missing enabled", []TransportRequest{{Protocol: "masque", Host: "vpn.example.org", Port: 443}}},
		{"production loopback", []TransportRequest{{Protocol: "ikev2", Host: "127.0.0.1", Port: 500, Enabled: boolPtr(true)}}},
		{"invalid priority", []TransportRequest{{Protocol: "proxy", Host: "vpn.example.org", Port: 443, Enabled: boolPtr(true), Priority: 1001}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateTransportRequests(test.items, true, false); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestEnabledServerTransport(t *testing.T) {
	server := &models.VPNServer{Transports: []models.TransportCapability{
		{Protocol: "wireguard", Host: "disabled.example.org", Port: 51820, Enabled: false},
		{Protocol: "wireguard", Host: "vpn.example.org", Port: 51820, Enabled: true, HealthStatus: "healthy"},
	}}
	transport, ok := enabledServerTransport(server, "wireguard")
	if !ok || transport.Host != "vpn.example.org" {
		t.Fatalf("expected enabled WireGuard transport, got %#v, %t", transport, ok)
	}
	server.Transports[1].HealthStatus = "degraded"
	if _, ok := enabledServerTransport(server, "wireguard"); ok {
		t.Fatal("non-healthy transport must not be selected")
	}
}

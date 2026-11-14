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

func TestWireGuardProxyOnlyTransportInventory(t *testing.T) {
	requests := []TransportRequest{
		{Protocol: "wireguard", Host: "edge.example.test", Port: 51820, Enabled: boolPtr(true), Priority: 100},
		{Protocol: "proxy", Host: "edge.example.test", Port: 8444, Enabled: boolPtr(true), Priority: 90},
	}
	transports, err := validateTransportRequests(requests, true, false)
	if err != nil {
		t.Fatalf("WireGuard/proxy inventory rejected: %v", err)
	}
	if len(transports) != 2 {
		t.Fatalf("expected exactly two capabilities, got %#v", transports)
	}
	server := &models.VPNServer{Transports: transports}
	for index, protocol := range []string{"wireguard", "proxy"} {
		if transports[index].Protocol != protocol || transports[index].HealthStatus != "unknown" {
			t.Fatalf("unexpected initial %s capability: %#v", protocol, transports[index])
		}
		if _, ok := enabledServerTransport(server, protocol); ok {
			t.Fatalf("%s selected before its health check", protocol)
		}
		server.Transports[index].HealthStatus = "healthy"
		if _, ok := enabledServerTransport(server, protocol); !ok {
			t.Fatalf("healthy %s capability was not selected", protocol)
		}
		server.Transports[index].Enabled = false
		if _, ok := enabledServerTransport(server, protocol); ok {
			t.Fatalf("disabled %s capability was selected", protocol)
		}
		server.Transports[index].Enabled = true
	}
	for _, protocol := range []string{"wss", "masque", "openvpn", "ikev2"} {
		if _, ok := enabledServerTransport(server, protocol); ok {
			t.Fatalf("deferred %s capability was manufactured", protocol)
		}
	}
}

func TestValidateOpenVPNMetadata(t *testing.T) {
	valid := map[string]interface{}{
		"server_name": "vpn.example.test",
		"dns":         []interface{}{"10.9.0.1", "2001:db8::53"},
		"health_file": "/run/midorivpn-health/openvpn.json",
		"certified":   false,
	}
	if err := validateOpenVPNMetadata(valid); err != nil {
		t.Fatalf("valid OpenVPN metadata rejected: %v", err)
	}
	for name, metadata := range map[string]map[string]interface{}{
		"external health": {"server_name": "vpn.example.test", "dns": []interface{}{"10.9.0.1"}, "health_url": "http://example.test:9194/healthz"},
		"external file":   {"server_name": "vpn.example.test", "dns": []interface{}{"10.9.0.1"}, "health_file": "/tmp/openvpn.json"},
		"both health":     {"server_name": "vpn.example.test", "dns": []interface{}{"10.9.0.1"}, "health_file": "/run/midorivpn-health/openvpn.json", "health_url": "http://127.0.0.1:9194/healthz"},
		"IP certificate":  {"server_name": "192.0.2.1", "dns": []interface{}{"10.9.0.1"}, "health_file": "/run/midorivpn-health/openvpn.json"},
		"invalid DNS":     {"server_name": "vpn.example.test", "dns": []interface{}{"resolver.invalid"}, "health_file": "/run/midorivpn-health/openvpn.json"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateOpenVPNMetadata(metadata); err == nil {
				t.Fatal("invalid OpenVPN metadata accepted")
			}
		})
	}
}

func TestValidateIKEv2Metadata(t *testing.T) {
	valid := map[string]interface{}{
		"server_name": "vpn.example.test",
		"health_file": "/run/midorivpn-health/ikev2.json",
		"dns":         []interface{}{"10.85.0.1"},
		"certified":   false,
	}
	if err := validateIKEv2Metadata(valid); err != nil {
		t.Fatalf("valid IKEv2 metadata rejected: %v", err)
	}
	for key, value := range map[string]interface{}{
		"server_name": "127.0.0.1",
		"health_file": "/tmp/attacker.json",
		"dns":         []interface{}{"not-an-ip"},
		"certified":   "yes",
	} {
		metadata := map[string]interface{}{
			"server_name": "vpn.example.test", "health_file": "/run/midorivpn-health/ikev2.json",
			"dns": []interface{}{"10.85.0.1"}, "certified": false,
		}
		metadata[key] = value
		if err := validateIKEv2Metadata(metadata); err == nil {
			t.Fatalf("invalid IKEv2 metadata %s=%v accepted", key, value)
		}
	}
}

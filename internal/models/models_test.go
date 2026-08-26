package models

import "testing"

func TestVPNServerApplyCapabilitiesRequiresExplicitTransports(t *testing.T) {
	server := VPNServer{IsActive: true, WGPort: 51820, PublicKey: "server-key"}

	server.ApplyCapabilities()

	if server.SupportsWireGuard {
		t.Fatal("WireGuard must not be advertised before a successful health check")
	}
	if server.SupportsProxy {
		t.Fatal("proxy must not be advertised before a successful health check")
	}
	if server.SupportsMeshExit {
		t.Fatal("mesh exit must not be advertised before a successful health check")
	}
	if len(server.Transports) != 0 {
		t.Fatalf("unconfigured server must not synthesize transports: %#v", server.Transports)
	}
}

func TestVPNServerApplyCapabilitiesRequiresHealthyTransport(t *testing.T) {
	server := VPNServer{IsActive: true}
	server.SetTransports([]TransportCapability{
		{Protocol: "wireguard", Host: "vpn.example.test", Port: 51820, Enabled: true, HealthStatus: "unknown"},
		{Protocol: "proxy", Host: "vpn.example.test", Port: 443, Enabled: true, HealthStatus: "degraded"},
	})
	server.ApplyCapabilities()
	if server.SupportsWireGuard || server.SupportsProxy || server.SupportsMeshExit {
		t.Fatal("unverified or degraded transports must not be advertised")
	}

	server.Transports[0].HealthStatus = "healthy"
	server.Transports[1].HealthStatus = "healthy"
	server.ApplyCapabilities()
	if !server.SupportsWireGuard || !server.SupportsProxy || !server.SupportsMeshExit {
		t.Fatal("healthy transports must be advertised")
	}
}

func TestVPNServerApplyCapabilitiesTunnelTransportsProvideWireGuard(t *testing.T) {
	server := VPNServer{IsActive: true}
	server.SetTransports([]TransportCapability{
		{Protocol: "wss", Enabled: true, HealthStatus: "healthy"},
		{Protocol: "masque", Enabled: true, HealthStatus: "healthy"},
	})
	server.ApplyCapabilities()
	if !server.SupportsWireGuard {
		t.Fatal("healthy WSS and MASQUE transports must provide WireGuard capability")
	}
}

func TestVPNServerApplyCapabilitiesInactive(t *testing.T) {
	server := VPNServer{
		IsActive:  false,
		WGPort:    51820,
		PublicKey: "server-key",
	}

	server.ApplyCapabilities()

	if server.SupportsWireGuard || server.SupportsProxy || server.SupportsMeshExit {
		t.Fatal("inactive server must not advertise capabilities")
	}
	if len(server.Transports) != 0 {
		t.Fatal("inactive server must not advertise transports")
	}
}

func TestCertificateTransportRequiresExplicitCertification(t *testing.T) {
	transport := TransportCapability{
		Protocol: "openvpn", Enabled: true, HealthStatus: "healthy",
		Metadata: map[string]interface{}{"certified": false},
	}
	if transport.IsUsable() {
		t.Fatal("healthy but uncertified OpenVPN must not be usable")
	}
	transport.Metadata["certified"] = true
	if !transport.IsUsable() {
		t.Fatal("healthy certified OpenVPN should be usable")
	}
}

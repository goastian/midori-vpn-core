package models

import "testing"

func TestVPNServerApplyCapabilities(t *testing.T) {
	server := VPNServer{
		IsActive:  true,
		WGPort:    51820,
		PublicKey: "server-key",
		ProxyPort: 8888,
	}

	server.ApplyCapabilities()

	if !server.SupportsWireGuard {
		t.Fatal("expected WireGuard support")
	}
	if !server.SupportsProxy {
		t.Fatal("expected proxy support")
	}
	if !server.SupportsMeshExit {
		t.Fatal("expected mesh exit support when proxy is enabled")
	}
}

func TestVPNServerApplyCapabilitiesInactive(t *testing.T) {
	server := VPNServer{
		IsActive:  false,
		WGPort:    51820,
		PublicKey: "server-key",
		ProxyPort: 8888,
	}

	server.ApplyCapabilities()

	if server.SupportsWireGuard || server.SupportsProxy || server.SupportsMeshExit {
		t.Fatal("inactive server must not advertise capabilities")
	}
}

package control

import (
	"strings"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/models"
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

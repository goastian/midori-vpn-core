package wg

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Run only inside a disposable network namespace with NET_ADMIN. Ordinary CI
// must not alter the runner's firewall; the separate container invocation uses
// the actual production image's iptables backend rather than a rule emulator.
func TestKernelFirewallTransactions(t *testing.T) {
	if os.Getenv("MIDORIVPN_KERNEL_FIREWALL_TEST") != "1" {
		t.Skip("requires a disposable container network namespace with NET_ADMIN")
	}
	if _, err := os.Stat("/run/.containerenv"); err != nil {
		t.Fatal("kernel firewall test requires a disposable Podman container")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Name != "lo" {
			t.Fatal("kernel firewall test requires --network=none, never host networking")
		}
	}
	iptables := func(args ...string) string {
		t.Helper()
		output, err := exec.Command("iptables", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("iptables %v: %v: %s", args, err, output)
		}
		return string(output)
	}
	manager := testManager(t, &fakeWireGuardClient{})
	manager.cfg.VpnDNS = "10.77.0.1"
	// Reproduce an old permissive rule without letting the new transaction
	// remove it or leave it ahead of the managed protection.
	iptables("-A", "INPUT", "-i", "wg-test", "-j", "ACCEPT")
	for range 2 {
		if err := manager.ensureNATRules(); err != nil {
			t.Fatal(err)
		}
	}
	input := iptables("-S", "INPUT")
	lines := strings.Split(strings.TrimSpace(input), "\n")
	if len(lines) < 3 || !strings.Contains(lines[1], "-j MVPN-IN-wg-test") ||
		strings.Count(input, "-j MVPN-IN-wg-test") != 1 ||
		!strings.Contains(input, "-A INPUT -i wg-test -j ACCEPT") {
		t.Fatalf("managed jump was not promoted/idempotent or changed the legacy rule: %s", input)
	}
	dns := iptables("-S", "MVPN-IN-wg-test")
	if strings.Count(dns, "--dport 53 -j ACCEPT") != 2 || !strings.Contains(dns, "-j DROP") {
		t.Fatalf("gateway DNS exception was not installed: %s", dns)
	}
	manager.cfg.VpnDNS = "1.1.1.1"
	if err := manager.ensureNATRules(); err != nil {
		t.Fatal(err)
	}
	if input = iptables("-S", "MVPN-IN-wg-test"); strings.Contains(input, "ACCEPT") || !strings.Contains(input, "-j DROP") {
		t.Fatalf("stale gateway DNS allowance survived reapplication: %s", input)
	}
	forward := iptables("-S", "MVPN-FW-wg-test")
	if !strings.Contains(forward, "-i wg-test -o wg-test -j DROP") ||
		!strings.Contains(forward, "--ctstate RELATED,ESTABLISHED -j ACCEPT") {
		t.Fatalf("kernel rejected/changed peer isolation or return rules: %s", forward)
	}
}

package wg

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
)

// ensureNATRules protects the namespace and isolates peers before enabling
// egress. Filter failures abort startup and bring even a preexisting interface
// down; NAT remains best-effort for deployments with externally managed NAT.
// All commands operate in the Core's current network namespace, never via nsenter.
func (m *Manager) ensureNATRules() (err error) {
	iface := m.cfg.WGInterface
	if len(iface) == 0 || len(iface) > 15 || strings.ContainsFunc(iface, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-')
	}) {
		return errors.New("invalid WireGuard firewall interface")
	}
	// Once the interface name is safe, every mandatory failure must stop an
	// existing data plane, not merely stop the API while kernel peers stay up.
	defer func() {
		if err == nil {
			return
		}
		out, stopErr := m.run("ip", "", "link", "set", "down", "dev", iface)
		if stopErr != nil {
			err = errors.Join(err, fmt.Errorf("cannot disable unprotected WireGuard interface %s: %w (output: %s)", iface, stopErr, strings.TrimSpace(string(out))))
		}
	}()
	_, subnet, err := net.ParseCIDR(m.cfg.Subnet)
	if err != nil || subnet.IP.To4() == nil || m.pool == nil {
		return errors.New("invalid WireGuard firewall IPv4 subnet or pool")
	}
	gateway, poolSubnet, err := net.ParseCIDR(m.pool.GatewayIP())
	if err != nil || poolSubnet.String() != subnet.String() {
		return errors.New("WireGuard firewall subnet does not match the address pool")
	}
	allowDNS := false
	for _, entry := range strings.Split(m.cfg.VpnDNS, ",") {
		if ip := net.ParseIP(strings.TrimSpace(entry)); ip != nil && ip.Equal(gateway) {
			allowDNS = true
		}
	}
	if err := m.installFirewall(iface, subnet.String(), gateway.String(), allowDNS); err != nil {
		return err
	}

	// No mesh NAT or permissive mesh exception: the MVP only offers VPN egress.
	// Keep preexisting NAT rules intact and identify new resources as ours.
	masq := []string{"POSTROUTING", "-s", subnet.String(), "!", "-o", iface, "-m", "comment", "--comment", "midorivpn-wg-" + iface + "-egress", "-j", "MASQUERADE"}
	if _, err := m.run("iptables", "", append([]string{"-w", "5", "-t", "nat", "-C"}, masq...)...); err != nil {
		if out, err := m.run("iptables", "", append([]string{"-w", "5", "-t", "nat", "-A"}, masq...)...); err != nil {
			slog.Warn("failed to add WireGuard MASQUERADE; internet egress may require externally managed NAT", "error", err, "output", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// MVPN-IN-/MVPN-FW-<interface> are reserved, MidoriVPN-managed chains. Updating
// them and promoting only our exact tagged jumps is one filter-table transaction:
// no flush of shared chains, duplicate jumps, stale DNS allowance or open window
// on reapplication. --noflush preserves all unrelated rules and base policies.
func (m *Manager) installFirewall(iface, subnet, gateway string, allowDNS bool) error {
	inputChain, forwardChain := "MVPN-IN-"+iface, "MVPN-FW-"+iface
	type jump struct {
		chain string
		rule  string
	}
	jumps := []jump{
		{"INPUT", "-i " + iface + " -m comment --comment midorivpn-wg-" + iface + "-input -j " + inputChain},
		{"FORWARD", "-o " + iface + " -m comment --comment midorivpn-wg-" + iface + "-return -j " + forwardChain},
		{"FORWARD", "-i " + iface + " -m comment --comment midorivpn-wg-" + iface + "-forward -j " + forwardChain},
	}
	listings := make(map[string]string)
	for _, chain := range []string{"INPUT", "FORWARD"} {
		out, err := m.run("iptables", "", "-w", "5", "-t", "filter", "-S", chain)
		if err != nil {
			return fmt.Errorf("inspect WireGuard firewall %s: %w (output: %s)", chain, err, strings.TrimSpace(string(out)))
		}
		listings[chain] = string(out)
	}
	var rules strings.Builder
	fmt.Fprintf(&rules, "*filter\n:%s - [0:0]\n:%s - [0:0]\n-F %s\n-F %s\n", inputChain, forwardChain, inputChain, forwardChain)
	if allowDNS {
		for _, protocol := range []string{"udp", "tcp"} {
			fmt.Fprintf(&rules, "-A %s -d %s -p %s --dport 53 -j ACCEPT\n", inputChain, gateway, protocol)
		}
	}
	// No broad ESTABLISHED exception in INPUT: old connections to local services
	// must be blocked too. The parent jump scopes this DROP to WG ingress only.
	fmt.Fprintf(&rules, "-A %s -j DROP\n", inputChain)
	for _, rule := range []string{
		"-i " + iface + " -o " + iface + " -j DROP",
		"-i " + iface + " -d " + subnet + " -j DROP",
		"-i " + iface + " -s " + subnet + " -j ACCEPT",
		"-o " + iface + " -d " + subnet + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-j DROP",
	} {
		fmt.Fprintf(&rules, "-A %s %s\n", forwardChain, rule)
	}
	for _, j := range jumps {
		expected := strings.Fields("-A " + j.chain + " " + j.rule)
		for _, line := range strings.Split(listings[j.chain], "\n") {
			fields := strings.Fields(line)
			// iptables -S may quote comments, including single-word comments.
			for i := range fields {
				fields[i] = strings.Trim(fields[i], `"`)
			}
			if slices.Equal(fields, expected) {
				fmt.Fprintf(&rules, "-D %s %s\n", j.chain, j.rule)
			}
		}
		// Insert rather than append so old untagged ACCEPT rules cannot bypass
		// isolation; leave those rules untouched for operational compatibility.
		fmt.Fprintf(&rules, "-I %s 1 %s\n", j.chain, j.rule)
	}
	rules.WriteString("COMMIT\n")
	if out, err := m.run("iptables-restore", rules.String(), "--wait", "5", "--noflush"); err != nil {
		return fmt.Errorf("install WireGuard isolation firewall: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

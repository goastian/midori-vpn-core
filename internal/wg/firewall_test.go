package wg

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/ippool"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// These tests execute the real firewall/startup code against a simulated command
// boundary. The simulator interprets emitted rules, including first-match order,
// user chains, conntrack and atomic restore; no host firewall commands are run.
type firewallPacket struct {
	in, out, source, destination, protocol, state string
	port                                          int
}

type firewallCommand struct {
	name, stdin string
	args        []string
}

type firewallSimulator struct {
	t        *testing.T
	tables   map[string]map[string][][]string
	commands []firewallCommand
	fail     func(firewallCommand) error
}

func newFirewallSimulator(t *testing.T) *firewallSimulator {
	t.Helper()
	return &firewallSimulator{t: t, tables: map[string]map[string][][]string{
		"filter": {"INPUT": nil, "FORWARD": nil, "OUTPUT": nil},
		"nat":    {"POSTROUTING": nil},
	}}
}

func (f *firewallSimulator) run(name, stdin string, args ...string) ([]byte, error) {
	c := firewallCommand{name: name, stdin: stdin, args: slices.Clone(args)}
	f.commands = append(f.commands, c)
	if f.fail != nil {
		if err := f.fail(c); err != nil {
			return []byte(err.Error()), err
		}
	}
	switch name {
	case "ip", "modprobe":
		return nil, nil
	case "iptables":
		table := "filter"
		for len(args) > 0 && (args[0] == "-w" || args[0] == "-t") {
			if args[0] == "-t" {
				table = args[1]
			}
			args = args[2:]
		}
		return f.apply(f.tables[table], args)
	case "iptables-restore":
		if !slices.Equal(args, []string{"--wait", "5", "--noflush"}) {
			f.t.Fatalf("unsafe restore options: %v", args)
		}
		candidate := make(map[string][][]string)
		for chain, rules := range f.tables["filter"] {
			candidate[chain] = slices.Clone(rules)
		}
		lines := strings.Split(strings.TrimSpace(stdin), "\n")
		if lines[0] != "*filter" || lines[len(lines)-1] != "COMMIT" {
			f.t.Fatalf("unexpected restore transaction: %s", stdin)
		}
		for _, line := range lines[1 : len(lines)-1] {
			fields := strings.Fields(line)
			if strings.HasPrefix(line, ":") {
				chain := strings.TrimPrefix(fields[0], ":")
				if _, exists := candidate[chain]; !exists {
					candidate[chain] = nil
				}
				continue
			}
			if _, err := f.apply(candidate, fields); err != nil {
				return nil, err
			}
		}
		f.tables["filter"] = candidate
		return nil, nil
	default:
		f.t.Fatalf("unexpected command: %s %v", name, args)
		return nil, errors.New("unexpected command")
	}
}

func (f *firewallSimulator) apply(chains map[string][][]string, args []string) ([]byte, error) {
	f.t.Helper()
	if len(args) < 2 {
		f.t.Fatalf("invalid iptables command: %v", args)
	}
	op, chain, rule := args[0], args[1], args[2:]
	rules, exists := chains[chain]
	if !exists {
		return nil, errors.New("chain does not exist")
	}
	switch op {
	case "-S":
		var output strings.Builder
		for _, r := range rules {
			// Match the quoting used by iptables -S for comment matches.
			r = slices.Clone(r)
			for i := 1; i < len(r); i++ {
				if r[i-1] == "--comment" {
					r[i] = strconv.Quote(r[i])
				}
			}
			fmt.Fprintf(&output, "-A %s %s\n", chain, strings.Join(r, " "))
		}
		return []byte(output.String()), nil
	case "-C", "-D":
		for i, r := range rules {
			if slices.Equal(r, rule) {
				if op == "-D" {
					chains[chain] = slices.Delete(slices.Clone(rules), i, i+1)
				}
				return nil, nil
			}
		}
		return nil, errors.New("rule does not exist")
	case "-A":
		chains[chain] = append(rules, slices.Clone(rule))
	case "-I":
		position, err := strconv.Atoi(rule[0])
		if err != nil || position < 1 || position > len(rules)+1 {
			f.t.Fatalf("invalid insert position: %v", args)
		}
		chains[chain] = slices.Insert(rules, position-1, slices.Clone(rule[1:]))
	case "-F":
		if chain == "INPUT" || chain == "FORWARD" || chain == "OUTPUT" {
			f.t.Fatalf("flushed an unmanaged chain: %s", chain)
		}
		chains[chain] = nil
	default:
		f.t.Fatalf("unexpected iptables operation: %v", args)
	}
	return nil, nil
}

func (f *firewallSimulator) verdict(chain string, packet firewallPacket) string {
	f.t.Helper()
	for _, rule := range f.tables["filter"][chain] {
		matches, target := true, ""
		negated := false
		for i := 0; i < len(rule); i++ {
			if rule[i] == "!" {
				negated = true
				continue
			}
			key, value := rule[i], rule[i+1]
			i++
			match := true
			switch key {
			case "-i":
				match = packet.in == value
			case "-o":
				match = packet.out == value
			case "-s", "-d":
				_, network, err := net.ParseCIDR(value)
				if err != nil {
					ip := net.ParseIP(value)
					network = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
				}
				address := packet.destination
				if key == "-s" {
					address = packet.source
				}
				match = network.Contains(net.ParseIP(address))
			case "-p":
				match = packet.protocol == value
			case "--dport":
				match = strconv.Itoa(packet.port) == value
			case "--ctstate":
				match = slices.Contains(strings.Split(value, ","), packet.state)
			case "-j":
				target = value
			case "-m", "--comment":
			default:
				f.t.Fatalf("unsupported firewall match: %v", rule)
			}
			if negated {
				match = !match
				negated = false
			}
			matches = matches && match
		}
		if !matches {
			continue
		}
		if target == "ACCEPT" || target == "DROP" || target == "REJECT" || target == "RETURN" {
			return target
		}
		if _, exists := f.tables["filter"][target]; !exists {
			f.t.Fatalf("unknown rule target: %s", target)
		}
		if verdict := f.verdict(target, packet); verdict != "RETURN" {
			return verdict
		}
	}
	if chain == "INPUT" || chain == "OUTPUT" {
		return "ACCEPT"
	}
	if chain == "FORWARD" {
		return "DROP"
	}
	return "RETURN"
}

func firewallTestManager(t *testing.T) (*Manager, *firewallSimulator) {
	t.Helper()
	m := testManager(t, &fakeWireGuardClient{})
	f := newFirewallSimulator(t)
	m.runCommand = f.run
	// Rules left by older Core versions, plus a common broad established rule.
	f.tables["filter"]["INPUT"] = [][]string{{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}, {"-j", "ACCEPT"}}
	f.tables["filter"]["FORWARD"] = [][]string{{"-i", m.cfg.WGInterface, "-j", "ACCEPT"}, {"-o", m.cfg.WGInterface, "-j", "ACCEPT"}, {"-i", "eth-admin", "-j", "ACCEPT"}}
	return m, f
}

func TestWireGuardFirewallBlocksNamespaceServices(t *testing.T) {
	m, f := firewallTestManager(t)
	if err := m.ensureNATRules(); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"10.77.0.1", "127.0.0.1", "192.0.2.10"} {
		for _, port := range []int{53, 80, 443, 5432, 6432, 6379, 8080, 9090, 9091, 8443, 51820} {
			for _, state := range []string{"NEW", "ESTABLISHED", "RELATED"} {
				p := firewallPacket{in: m.cfg.WGInterface, source: "10.77.0.2", destination: destination, protocol: "tcp", port: port, state: state}
				if got := f.verdict("INPUT", p); got != "DROP" {
					t.Errorf("namespace service %s:%d (%s) = %s, want DROP", destination, port, state, got)
				}
			}
		}
	}
	for _, iface := range []string{"eth-admin", "lo", "wg-management"} {
		if got := f.verdict("INPUT", firewallPacket{in: iface, destination: "192.0.2.10", port: 5432}); got != "ACCEPT" {
			t.Errorf("unrelated INPUT on %s changed: %s", iface, got)
		}
	}
}

func TestWireGuardFirewallDNSIsExplicitAndReconciled(t *testing.T) {
	m, f := firewallTestManager(t)
	for _, tc := range []struct {
		dns     string
		gateway bool
	}{
		{"1.1.1.1", false},
		{" 1.1.1.1, 10.77.0.1 ,2001:db8::53", true},
		{"10.77.0.10", false},
		{"10.77.0.1", true},
		{"", false},
	} {
		m.cfg.VpnDNS = tc.dns
		if err := m.ensureNATRules(); err != nil {
			t.Fatal(err)
		}
		for _, protocol := range []string{"tcp", "udp", "icmp"} {
			for _, destination := range []string{"10.77.0.1", "192.0.2.10"} {
				for _, port := range []int{53, 853, 5432} {
					want := "DROP"
					if tc.gateway && destination == "10.77.0.1" && port == 53 && protocol != "icmp" {
						want = "ACCEPT"
					}
					packet := firewallPacket{in: m.cfg.WGInterface, source: "10.77.0.2", destination: destination, protocol: protocol, port: port}
					if got := f.verdict("INPUT", packet); got != want {
						t.Errorf("DNS=%q %s %s:%d = %s, want %s", tc.dns, protocol, destination, port, got, want)
					}
				}
			}
		}
		if got := f.verdict("FORWARD", firewallPacket{in: m.cfg.WGInterface, out: "eth0", source: "10.77.0.2", destination: "1.1.1.1", protocol: "udp", port: 53}); got != "ACCEPT" {
			t.Errorf("external DNS egress = %s", got)
		}
	}
}

func TestWireGuardFirewallIsolatesClientsWithoutMeshBypass(t *testing.T) {
	m, f := firewallTestManager(t)
	m.meshIPs["peer-a"] = "10.200.1.2"
	m.meshIPs["peer-b"] = "10.200.1.3"
	if err := m.ensureNATRules(); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"10.77.0.2", "10.200.1.2"} {
		for _, destination := range []string{"10.77.0.3", "10.200.1.3"} {
			for _, state := range []string{"NEW", "ESTABLISHED", "RELATED"} {
				packet := firewallPacket{in: m.cfg.WGInterface, out: m.cfg.WGInterface, source: source, destination: destination, state: state}
				if got := f.verdict("FORWARD", packet); got != "DROP" {
					t.Errorf("client %s -> %s (%s) = %s", source, destination, state, got)
				}
			}
		}
	}
	if got := f.verdict("FORWARD", firewallPacket{in: m.cfg.WGInterface, out: "eth0", source: "10.77.0.2", destination: "10.77.0.3"}); got != "DROP" {
		t.Errorf("VPN destination routed via another interface = %s", got)
	}
	for _, state := range []string{"NEW", "ESTABLISHED"} {
		if got := f.verdict("FORWARD", firewallPacket{in: m.cfg.WGInterface, out: "eth0", source: "10.77.0.2", destination: "203.0.113.80", protocol: "tcp", port: 443, state: state}); got != "ACCEPT" {
			t.Errorf("internet egress (%s) = %s", state, got)
		}
	}
	for _, state := range []string{"ESTABLISHED", "RELATED"} {
		if got := f.verdict("FORWARD", firewallPacket{in: "eth0", out: m.cfg.WGInterface, source: "203.0.113.80", destination: "10.77.0.2", state: state}); got != "ACCEPT" {
			t.Errorf("internet return traffic (%s) = %s", state, got)
		}
	}
	if got := f.verdict("FORWARD", firewallPacket{in: "eth-admin", out: "eth0", source: "192.0.2.2", destination: "203.0.113.80"}); got != "ACCEPT" {
		t.Errorf("unrelated forwarding changed: %s", got)
	}
}

func TestWireGuardFirewallReapplicationPreservesUnmanagedRules(t *testing.T) {
	m, f := firewallTestManager(t)
	legacyNAT := [][]string{
		{"-s", m.cfg.Subnet, "-j", "MASQUERADE"},
		{"-s", "10.200.0.0/16", "-j", "MASQUERADE"},
		{"-s", "192.0.2.0/24", "-o", "eth-admin", "-j", "MASQUERADE"},
	}
	f.tables["nat"]["POSTROUTING"] = slices.Clone(legacyNAT)
	foreignChain := [][]string{{"-p", "tcp", "--dport", "8443", "-j", "ACCEPT"}}
	f.tables["filter"]["ADMIN-POLICY"] = slices.Clone(foreignChain)
	originalInput := slices.Clone(f.tables["filter"]["INPUT"])
	originalForward := slices.Clone(f.tables["filter"]["FORWARD"])
	if err := m.ensureNATRules(); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprint(f.tables)
	for range 3 {
		if err := m.ensureNATRules(); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(f.tables); got != want {
			t.Fatal("reapplication changed or duplicated firewall rules")
		}
	}
	if !reflect.DeepEqual(f.tables["nat"]["POSTROUTING"][:len(legacyNAT)], legacyNAT) || !reflect.DeepEqual(f.tables["filter"]["ADMIN-POLICY"], foreignChain) {
		t.Fatal("preexisting NAT or unrelated user chain was changed")
	}
	for chain, original := range map[string][][]string{"INPUT": originalInput, "FORWARD": originalForward} {
		rules := f.tables["filter"][chain]
		if !reflect.DeepEqual(rules[len(rules)-len(original):], original) {
			t.Errorf("preexisting %s rules were changed: %v", chain, rules)
		}
		// Simulate an administrator prepending ACCEPT, as can happen on restart.
		f.tables["filter"][chain] = slices.Insert(rules, 0, []string{"-j", "ACCEPT"})
	}
	if err := m.ensureNATRules(); err != nil {
		t.Fatal(err)
	}
	if got := f.verdict("INPUT", firewallPacket{in: m.cfg.WGInterface, destination: "10.77.0.1", port: 5432}); got != "DROP" {
		t.Errorf("preexisting ACCEPT preceded local isolation: %s", got)
	}
	if got := f.verdict("FORWARD", firewallPacket{in: m.cfg.WGInterface, out: m.cfg.WGInterface, source: "10.77.0.2", destination: "10.77.0.3"}); got != "DROP" {
		t.Errorf("preexisting ACCEPT preceded client isolation: %s", got)
	}
}

func TestWireGuardFirewallUsesPoolGatewayAndConfiguredInterface(t *testing.T) {
	m, f := firewallTestManager(t)
	m.cfg.WGInterface = "vpn-special_1"
	m.cfg.Subnet = "10.90.6.99/22"
	m.cfg.VpnDNS = "10.90.4.1"
	pool, err := ippool.New(m.cfg.Subnet)
	if err != nil {
		t.Fatal(err)
	}
	m.pool = pool
	if err := m.ensureNATRules(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		destination, want string
	}{{"10.90.4.1", "ACCEPT"}, {"10.90.6.1", "DROP"}, {"10.77.0.1", "DROP"}} {
		if got := f.verdict("INPUT", firewallPacket{in: m.cfg.WGInterface, destination: tc.destination, protocol: "udp", port: 53}); got != tc.want {
			t.Errorf("gateway DNS %s = %s, want %s", tc.destination, got, tc.want)
		}
	}
	if got := f.verdict("FORWARD", firewallPacket{in: m.cfg.WGInterface, out: "eth0", source: "10.90.7.2", destination: "10.90.4.2"}); got != "DROP" {
		t.Errorf("non-/24 subnet isolation = %s", got)
	}
}

func TestWireGuardStartupFailsClosedWhenProtectionCannotBeInstalled(t *testing.T) {
	for _, path := range []string{"existing", "new", "restored"} {
		for _, failure := range []string{"INPUT", "FORWARD", "restore"} {
			t.Run(path+"/"+failure, func(t *testing.T) {
				m, f := firewallTestManager(t)
				client := m.client.(*fakeWireGuardClient)
				client.device.PrivateKey = wgtypes.Key{1}
				if path != "existing" {
					client.deviceErr = errors.New("device missing")
				}
				if path == "restored" {
					conf := "[Interface]\nPrivateKey = " + testKey(3) + "\n[Peer]\nPublicKey = " + testKey(4) + "\nAllowedIPs = 10.77.0.2/32\n"
					if err := os.WriteFile(filepath.Join(m.cfg.ConfigDir, m.cfg.WGInterface+".conf"), []byte(conf), 0600); err != nil {
						t.Fatal(err)
					}
				}
				f.fail = func(c firewallCommand) error {
					if failure == "restore" && c.name == "iptables-restore" || c.name == "iptables" && slices.Contains(c.args, "-S") && slices.Contains(c.args, failure) {
						return errors.New("no firewall permission")
					}
					return nil
				}
				if err := m.ensureInterface(); err == nil {
					t.Fatal("startup succeeded without required protection")
				}
				if client.configureCalls != 0 {
					t.Fatal("startup configured peers before installing isolation")
				}
				down := false
				for _, c := range f.commands {
					if c.name == "ip" && slices.Equal(c.args, []string{"link", "set", "down", "dev", m.cfg.WGInterface}) {
						down = true
					}
					if c.name == "ip" && slices.Contains(c.args, "up") || slices.Contains(c.args, "nat") {
						t.Errorf("enabled forwarding before protection: %+v", c)
					}
				}
				if !down {
					t.Fatal("existing interface was not brought down on protection failure")
				}
			})
		}
	}
}

func TestWireGuardFirewallProtectsFreshNamespaceAndRejectsUnsolicitedIngress(t *testing.T) {
	m, f := firewallTestManager(t)
	f.tables["filter"]["INPUT"] = nil
	f.tables["filter"]["FORWARD"] = nil
	if err := m.ensureNATRules(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		packet firewallPacket
		want   string
	}{
		{firewallPacket{in: m.cfg.WGInterface, out: "eth0", source: "10.77.0.2", destination: "203.0.113.80", state: "NEW"}, "ACCEPT"},
		{firewallPacket{in: "eth0", out: m.cfg.WGInterface, source: "203.0.113.80", destination: "10.77.0.2", state: "ESTABLISHED"}, "ACCEPT"},
		{firewallPacket{in: "eth0", out: m.cfg.WGInterface, source: "203.0.113.80", destination: "10.77.0.2", state: "NEW"}, "DROP"},
		{firewallPacket{in: m.cfg.WGInterface, out: "eth0", source: "192.0.2.2", destination: "203.0.113.80", state: "NEW"}, "DROP"},
		{firewallPacket{in: m.cfg.WGInterface, out: "eth0", source: "10.200.1.2", destination: "203.0.113.80", state: "NEW"}, "DROP"},
	} {
		if got := f.verdict("FORWARD", tc.packet); got != tc.want {
			t.Errorf("FORWARD %+v = %s, want %s", tc.packet, got, tc.want)
		}
	}
	if got := f.verdict("INPUT", firewallPacket{in: m.cfg.WGInterface, destination: "10.77.0.1", port: 5432}); got != "DROP" {
		t.Errorf("fresh namespace INPUT = %s", got)
	}
	if got := f.verdict("OUTPUT", firewallPacket{out: "eth0", destination: "203.0.113.80"}); got != "ACCEPT" {
		t.Errorf("namespace OUTPUT changed = %s", got)
	}
}

func TestWireGuardFirewallDeduplicatesOnlyItsOwnJumps(t *testing.T) {
	m, f := firewallTestManager(t)
	if err := m.ensureNATRules(); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprint(f.tables)
	for _, chain := range []string{"INPUT", "FORWARD"} {
		rules := f.tables["filter"][chain]
		count := 1
		if chain == "FORWARD" {
			count = 2
		}
		duplicates := slices.Clone(rules[:count])
		f.tables["filter"][chain] = append(rules, duplicates...)
	}
	if err := m.ensureNATRules(); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(f.tables); got != want {
		t.Fatal("tagged duplicate jumps were not reconciled to the original ruleset")
	}
}

func TestWireGuardStartupInstallsProtectionBeforeInterfaceOrPeers(t *testing.T) {
	for _, path := range []string{"existing", "existing-zero-key", "new", "restored", "api-fallback"} {
		t.Run(path, func(t *testing.T) {
			m, f := firewallTestManager(t)
			client := m.client.(*fakeWireGuardClient)
			if path == "existing" {
				client.device.PrivateKey = wgtypes.Key{1}
			} else if path != "existing-zero-key" {
				client.deviceErr = errors.New("device missing")
			}
			if path == "restored" {
				conf := "[Interface]\nPrivateKey = " + testKey(3) + "\n[Peer]\nPublicKey = " + testKey(4) + "\nAllowedIPs = 10.77.0.2/32\n"
				if err := os.WriteFile(filepath.Join(m.cfg.ConfigDir, m.cfg.WGInterface+".conf"), []byte(conf), 0600); err != nil {
					t.Fatal(err)
				}
			}
			assertProtected := func() {
				t.Helper()
				if got := f.verdict("INPUT", firewallPacket{in: m.cfg.WGInterface, destination: "10.77.0.1", protocol: "tcp", port: 5432}); got != "DROP" {
					t.Fatal("interface/peers enabled before namespace protection")
				}
				if got := f.verdict("FORWARD", firewallPacket{in: m.cfg.WGInterface, out: m.cfg.WGInterface, source: "10.77.0.2", destination: "10.77.0.3"}); got != "DROP" {
					t.Fatal("interface/peers enabled before client isolation")
				}
			}
			client.configureHook = assertProtected
			m.runCommand = func(name, stdin string, args ...string) ([]byte, error) {
				if name == "ip" && slices.Contains(args, "up") {
					assertProtected()
				}
				return f.run(name, stdin, args...)
			}
			f.fail = func(c firewallCommand) error {
				if c.name == "ip" && slices.Contains(c.args, "show") && path != "existing" && path != "existing-zero-key" {
					return errors.New("link missing")
				}
				if c.name == "ip" && slices.Contains(c.args, "add") && path == "api-fallback" {
					return errors.New("Operation not permitted")
				}
				return nil
			}
			if err := m.ensureInterface(); err != nil {
				t.Fatal(err)
			}
			assertProtected()
			if path != "existing" && client.configureCalls != 1 {
				t.Errorf("configuration calls = %d, want 1", client.configureCalls)
			}
		})
	}
}

func TestWireGuardFirewallFailureReportsDisableFailure(t *testing.T) {
	m, f := firewallTestManager(t)
	protectionErr := errors.New("iptables-restore unavailable")
	disableErr := errors.New("cannot bring interface down")
	f.fail = func(c firewallCommand) error {
		if c.name == "iptables-restore" {
			return protectionErr
		}
		if c.name == "ip" && slices.Contains(c.args, "down") {
			return disableErr
		}
		return nil
	}
	if err := m.ensureInterface(); !errors.Is(err, protectionErr) || !errors.Is(err, disableErr) {
		t.Fatalf("protection/disable failures not both reported: %v", err)
	}
}

func TestWireGuardStartupRecoversAfterFailClosedShutdown(t *testing.T) {
	m, f := firewallTestManager(t)
	m.client.(*fakeWireGuardClient).device.PrivateKey = wgtypes.Key{1}
	down := false
	f.fail = func(c firewallCommand) error {
		if c.name == "iptables-restore" {
			return errors.New("temporary protection failure")
		}
		return nil
	}
	m.runCommand = func(name, stdin string, args ...string) ([]byte, error) {
		if name == "ip" && slices.Contains(args, "down") {
			down = true
		}
		if name == "ip" && slices.Contains(args, "up") {
			if got := f.verdict("INPUT", firewallPacket{in: m.cfg.WGInterface, destination: "10.77.0.1", port: 5432}); got != "DROP" {
				t.Fatal("recovery brought interface up without protection")
			}
			down = false
		}
		return f.run(name, stdin, args...)
	}
	if err := m.ensureInterface(); err == nil || !down {
		t.Fatalf("initial failure did not disable interface: down=%v err=%v", down, err)
	}
	f.fail = nil
	if err := m.ensureInterface(); err != nil {
		t.Fatal(err)
	}
	if down {
		t.Fatal("protected retry left interface disabled, breaking egress")
	}
}

func TestWireGuardFirewallNATFailureDoesNotRelaxProtection(t *testing.T) {
	m, f := firewallTestManager(t)
	f.fail = func(c firewallCommand) error {
		if c.name == "iptables" && slices.Contains(c.args, "nat") {
			return errors.New("NAT externally managed")
		}
		return nil
	}
	if err := m.ensureInterface(); err != nil {
		t.Fatalf("optional NAT prevented protected startup: %v", err)
	}
	if got := f.verdict("INPUT", firewallPacket{in: m.cfg.WGInterface, destination: "10.77.0.1", port: 5432}); got != "DROP" {
		t.Errorf("INPUT after NAT failure = %s", got)
	}
	if got := f.verdict("FORWARD", firewallPacket{in: m.cfg.WGInterface, out: m.cfg.WGInterface, source: "10.77.0.2", destination: "10.77.0.3"}); got != "DROP" {
		t.Errorf("client isolation after NAT failure = %s", got)
	}
}

func TestWireGuardFirewallRejectsUnsafeRuleInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Manager)
	}{
		{"empty interface", func(m *Manager) { m.cfg.WGInterface = "" }},
		{"wildcard interface", func(m *Manager) { m.cfg.WGInterface = "wg+" }},
		{"oversized interface", func(m *Manager) { m.cfg.WGInterface = strings.Repeat("w", 16) }},
		{"restore injection", func(m *Manager) { m.cfg.WGInterface = "wg\n-P INPUT ACCEPT" }},
		{"invalid subnet", func(m *Manager) { m.cfg.Subnet = "10.77.0.0/24\n-P INPUT ACCEPT" }},
		{"IPv6 subnet", func(m *Manager) { m.cfg.Subnet = "2001:db8::/64" }},
		{"mismatched pool", func(m *Manager) { m.cfg.Subnet = "10.90.0.0/24" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, f := firewallTestManager(t)
			tc.change(m)
			if err := m.ensureNATRules(); err == nil {
				t.Fatal("unsafe firewall configuration was accepted")
			}
			for _, c := range f.commands {
				if c.name == "iptables" || c.name == "iptables-restore" {
					t.Fatalf("invalid configuration reached firewall: %+v", c)
				}
			}
		})
	}
}

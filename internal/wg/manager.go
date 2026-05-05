package wg

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/crypto"
	"github.com/goastian/midori-vpn-core/internal/ippool"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerInfo struct {
	PublicKey     string     `json:"public_key"`
	AllowedIP     string     `json:"allowed_ip"`
	Keepalive     int        `json:"keepalive"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	TransmitBytes int64      `json:"tx_bytes"`
	ReceiveBytes  int64      `json:"rx_bytes"`
	Endpoint      string     `json:"endpoint,omitempty"`
}

type ServerStatsResponse struct {
	Interface  string `json:"interface"`
	PublicKey  string `json:"public_key"`
	ListenPort int    `json:"listen_port"`
	PeerCount  int    `json:"peer_count"`
	TotalTX    int64  `json:"total_tx_bytes"`
	TotalRX    int64  `json:"total_rx_bytes"`
}

type Manager struct {
	mu         sync.Mutex
	cfg        *config.Config
	client     *wgctrl.Client
	pool       *ippool.Pool
	peerIPs    map[string]string // pubkey -> allocated VPN pool IP (e.g. "10.8.0.5/32")
	meshIPs    map[string]string // pubkey -> mesh overlay IP  (e.g. "10.200.1.2")
	privateKey wgtypes.Key
}

func NewManager(cfg *config.Config) (*Manager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl.New: %w (is WireGuard kernel module loaded?)", err)
	}

	pool, err := ippool.New(cfg.Subnet)
	if err != nil {
		return nil, fmt.Errorf("ippool.New: %w", err)
	}

	m := &Manager{
		cfg:     cfg,
		client:  client,
		pool:    pool,
		peerIPs: make(map[string]string),
		meshIPs: make(map[string]string),
	}

	if err := m.ensureInterface(); err != nil {
		client.Close()
		return nil, err
	}

	if err := m.loadExistingPeers(); err != nil {
		slog.Warn("could not load existing peers", "error", err)
	}

	return m, nil
}

func (m *Manager) Close() {
	m.client.Close()
}

// PublicKey returns the server's WireGuard public key in base64.
func (m *Manager) PublicKey() string {
	// Derive public key from private key via Curve25519
	pubKey := m.privateKey.PublicKey()
	return base64.StdEncoding.EncodeToString(pubKey[:])
}

func (m *Manager) ensureInterface() error {
	dev, err := m.client.Device(m.cfg.WGInterface)
	if err != nil {
		slog.Info("interface not found, attempting to configure", "interface", m.cfg.WGInterface)
		confPath := filepath.Join(m.cfg.ConfigDir, m.cfg.WGInterface+".conf")
		if _, statErr := os.Stat(confPath); statErr == nil {
			slog.Info("found saved config, restoring interface and peers", "path", confPath)
			return m.restoreFromConfig(confPath)
		}
		return m.configureNewInterface()
	}

	m.privateKey = dev.PrivateKey
	pubKey := base64.StdEncoding.EncodeToString(dev.PublicKey[:])
	slog.Info("interface already exists", "interface", m.cfg.WGInterface, "listen_port", dev.ListenPort, "peers", len(dev.Peers), "public_key", pubKey)
	if err := m.ensureNATRules(); err != nil {
		return fmt.Errorf("ensureInterface: %w", err)
	}
	return nil
}

func (m *Manager) createNetworkInterface() error {
	iface := m.cfg.WGInterface

	// Create the WireGuard network interface
	if out, err := exec.Command("ip", "link", "add", "dev", iface, "type", "wireguard").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link add %s: %s: %w", iface, strings.TrimSpace(string(out)), err)
	}

	// Assign the gateway IP from the subnet to the interface
	gatewayIP := m.pool.GatewayIP()
	if out, err := exec.Command("ip", "address", "add", "dev", iface, gatewayIP).CombinedOutput(); err != nil {
		return fmt.Errorf("ip address add %s: %s: %w", gatewayIP, strings.TrimSpace(string(out)), err)
	}

	// Bring the interface up
	if out, err := exec.Command("ip", "link", "set", "up", "dev", iface).CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up %s: %s: %w", iface, strings.TrimSpace(string(out)), err)
	}

	slog.Info("created network interface", "interface", iface, "address", gatewayIP)
	if err := m.ensureNATRules(); err != nil {
		return fmt.Errorf("createNetworkInterface: %w", err)
	}
	return nil
}

func (m *Manager) configureNewInterface() error {
	// First create the WireGuard network interface via ip(8)
	if err := m.createNetworkInterface(); err != nil {
		return err
	}

	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("generate server keypair: %w", err)
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil {
		return err
	}

	var privKey wgtypes.Key
	copy(privKey[:], privKeyBytes)
	m.privateKey = privKey

	port := m.cfg.WGPort
	wgCfg := wgtypes.Config{
		PrivateKey: &privKey,
		ListenPort: &port,
	}

	if err := m.client.ConfigureDevice(m.cfg.WGInterface, wgCfg); err != nil {
		return fmt.Errorf("configure device %s: %w", m.cfg.WGInterface, err)
	}

	m.persistConfig()
	slog.Info("configured interface", "interface", m.cfg.WGInterface, "port", port, "public_key", kp.PublicKey)
	return nil
}

// restoreFromConfig recreates the WireGuard interface from a previously-persisted
// wg0.conf file. This preserves the server keypair and restores all peer entries
// so that clients do not need to reconfigure after a container restart.
func (m *Manager) restoreFromConfig(confPath string) error {
	data, err := os.ReadFile(confPath)
	if err != nil {
		slog.Warn("restore: cannot read saved config, creating fresh interface", "path", confPath, "error", err)
		return m.configureNewInterface()
	}

	type peerConf struct {
		pubkey     wgtypes.Key
		allowedIPs []net.IPNet
		keepalive  time.Duration
	}

	var privKey wgtypes.Key
	var privKeyFound bool
	var peers []peerConf
	var curPeer *peerConf

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case line == "[Interface]":
			if curPeer != nil {
				peers = append(peers, *curPeer)
				curPeer = nil
			}
		case line == "[Peer]":
			if curPeer != nil {
				peers = append(peers, *curPeer)
			}
			curPeer = &peerConf{}
		default:
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			if curPeer == nil {
				if k == "PrivateKey" {
					raw, decErr := base64.StdEncoding.DecodeString(v)
					if decErr == nil && len(raw) == 32 {
						copy(privKey[:], raw)
						privKeyFound = true
					}
				}
			} else {
				switch k {
				case "PublicKey":
					raw, decErr := base64.StdEncoding.DecodeString(v)
					if decErr != nil || len(raw) != 32 {
						slog.Warn("restore: invalid peer public key, skipping", "key", v)
						curPeer = nil
						continue
					}
					copy(curPeer.pubkey[:], raw)
				case "AllowedIPs":
					for _, cidr := range strings.Split(v, ",") {
						cidr = strings.TrimSpace(cidr)
						_, ipNet, parseErr := net.ParseCIDR(cidr)
						if parseErr == nil {
							curPeer.allowedIPs = append(curPeer.allowedIPs, *ipNet)
						}
					}
				case "PersistentKeepalive":
					if secs, convErr := strconv.Atoi(v); convErr == nil {
						curPeer.keepalive = time.Duration(secs) * time.Second
					}
				}
			}
		}
	}
	if curPeer != nil {
		peers = append(peers, *curPeer)
	}

	if !privKeyFound {
		slog.Warn("restore: no valid PrivateKey found in saved config, creating fresh interface", "path", confPath)
		return m.configureNewInterface()
	}

	// Recreate the network namespace interface.
	if err := m.createNetworkInterface(); err != nil {
		return err
	}
	m.privateKey = privKey

	// Build WireGuard device config: private key + listen port + all saved peers.
	peerCfgs := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, p := range peers {
		pc := wgtypes.PeerConfig{
			PublicKey:  p.pubkey,
			AllowedIPs: p.allowedIPs,
		}
		if p.keepalive > 0 {
			pc.PersistentKeepaliveInterval = &p.keepalive
		}
		peerCfgs = append(peerCfgs, pc)
	}
	port := m.cfg.WGPort
	wgCfg := wgtypes.Config{
		PrivateKey: &privKey,
		ListenPort: &port,
		Peers:      peerCfgs,
	}
	if err := m.client.ConfigureDevice(m.cfg.WGInterface, wgCfg); err != nil {
		return fmt.Errorf("restore: configure device: %w", err)
	}

	pubKey := m.privateKey.PublicKey()
	slog.Info("restored interface from saved config",
		"interface", m.cfg.WGInterface,
		"port", m.cfg.WGPort,
		"public_key", base64.StdEncoding.EncodeToString(pubKey[:]),
		"peers_restored", len(peers),
	)
	return nil
}

// ensureNATRules idempotently adds the iptables rules needed to forward and
// masquerade traffic from WireGuard peers to the internet.
// Called on interface creation and on startup (in case rules were lost after
// a container restart with a pre-existing interface).
//
// MASQUERADE (NAT) failure is treated as a warning — some host environments
// (e.g. kernels using nf_tables without legacy compat) do not support it
// inside containers. The VPN can still route peer-to-peer traffic; internet
// NAT must be configured on the host in that case.
// FORWARD rule failures are returned as hard errors because without them
// the kernel will silently drop all VPN traffic.
func (m *Manager) ensureNATRules() error {
	iface := m.cfg.WGInterface
	subnet := m.cfg.Subnet

	// Best-effort MASQUERADE rule: warn and continue on failure.
	masqCheck := []string{"iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"}
	masqAdd := []string{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"}
	if err := exec.Command(masqCheck[0], masqCheck[1:]...).Run(); err != nil {
		if out, addErr := exec.Command(masqAdd[0], masqAdd[1:]...).CombinedOutput(); addErr != nil {
			slog.Warn("failed to add iptables MASQUERADE rule — internet access for VPN peers may require host-level NAT",
				"error", addErr,
				"output", strings.TrimSpace(string(out)),
			)
		} else {
			slog.Info("added iptables rule", "rule", strings.Join(masqAdd[3:], " "))
		}
	}

	// Best-effort MASQUERADE for the mesh overlay subnet so that mesh peers
	// can reach the internet through this server.
	const meshSubnet = "10.200.0.0/16"
	meshMasqCheck := []string{"iptables", "-t", "nat", "-C", "POSTROUTING", "-s", meshSubnet, "-j", "MASQUERADE"}
	meshMasqAdd := []string{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", meshSubnet, "-j", "MASQUERADE"}
	if err := exec.Command(meshMasqCheck[0], meshMasqCheck[1:]...).Run(); err != nil {
		if out, addErr := exec.Command(meshMasqAdd[0], meshMasqAdd[1:]...).CombinedOutput(); addErr != nil {
			slog.Warn("failed to add mesh MASQUERADE rule — mesh internet access may require host-level NAT",
				"error", addErr,
				"output", strings.TrimSpace(string(out)),
			)
		} else {
			slog.Info("added iptables rule", "rule", strings.Join(meshMasqAdd[3:], " "))
		}
	}

	// Mandatory FORWARD rules: return an error if these fail, because without
	// them the kernel drops all traffic through the WireGuard interface.
	type rule struct {
		check []string
		add   []string
	}
	forwardRules := []rule{
		{
			check: []string{"iptables", "-C", "FORWARD", "-i", iface, "-j", "ACCEPT"},
			add:   []string{"iptables", "-A", "FORWARD", "-i", iface, "-j", "ACCEPT"},
		},
		{
			check: []string{"iptables", "-C", "FORWARD", "-o", iface, "-j", "ACCEPT"},
			add:   []string{"iptables", "-A", "FORWARD", "-o", iface, "-j", "ACCEPT"},
		},
	}
	for _, r := range forwardRules {
		if err := exec.Command(r.check[0], r.check[1:]...).Run(); err != nil {
			if out, addErr := exec.Command(r.add[0], r.add[1:]...).CombinedOutput(); addErr != nil {
				return fmt.Errorf("iptables rule %q: %w (output: %s)",
					strings.Join(r.add[3:], " "), addErr, strings.TrimSpace(string(out)))
			}
			slog.Info("added iptables rule", "rule", strings.Join(r.add[3:], " "))
		}
	}
	return nil
}

func (m *Manager) loadExistingPeers() error {
	dev, err := m.client.Device(m.cfg.WGInterface)
	if err != nil {
		return err
	}

	for _, peer := range dev.Peers {
		pubkey := base64.StdEncoding.EncodeToString(peer.PublicKey[:])
		for _, aip := range peer.AllowedIPs {
			ip := aip.IP.String()
			if meshIPNet != nil && meshIPNet.Contains(aip.IP) {
				m.meshIPs[pubkey] = ip
			} else {
				m.peerIPs[pubkey] = ip + "/32"
				_ = m.pool.Reserve(ip)
			}
		}
	}

	slog.Info("loaded existing peers", "count", len(dev.Peers), "interface", m.cfg.WGInterface)
	return nil
}

// --- Public API ---

func (m *Manager) AddPeer(pubkeyStr string, keepalive int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.peerIPs[pubkeyStr]; exists {
		return "", errors.New("peer already exists")
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubkeyStr)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	var pubKey wgtypes.Key
	copy(pubKey[:], pubKeyBytes)

	allocatedIP, err := m.pool.Allocate()
	if err != nil {
		return "", fmt.Errorf("IP allocation: %w", err)
	}

	_, ipNet, err := net.ParseCIDR(allocatedIP)
	if err != nil {
		_ = m.pool.Release(allocatedIP)
		return "", fmt.Errorf("internal: invalid allocated IP %q: %w", allocatedIP, err)
	}

	ka := time.Duration(keepalive) * time.Second
	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   pubKey,
		AllowedIPs:                  []net.IPNet{*ipNet},
		PersistentKeepaliveInterval: &ka,
	}

	if err := m.client.ConfigureDevice(m.cfg.WGInterface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		_ = m.pool.Release(allocatedIP)
		return "", fmt.Errorf("configure peer: %w", err)
	}

	m.peerIPs[pubkeyStr] = allocatedIP
	m.persistConfig()

	return allocatedIP, nil
}

func (m *Manager) RemovePeer(pubkeyStr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubkeyStr)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	var pubKey wgtypes.Key
	copy(pubKey[:], pubKeyBytes)

	peerCfg := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	if err := m.client.ConfigureDevice(m.cfg.WGInterface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}

	if ip, ok := m.peerIPs[pubkeyStr]; ok {
		_ = m.pool.Release(ip)
		delete(m.peerIPs, pubkeyStr)
	}

	m.persistConfig()
	return nil
}

func (m *Manager) UpdatePeer(pubkeyStr string, keepalive int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubkeyStr)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	var pubKey wgtypes.Key
	copy(pubKey[:], pubKeyBytes)

	ip, ok := m.peerIPs[pubkeyStr]
	if !ok {
		return errors.New("peer not found")
	}

	_, ipNet, err := net.ParseCIDR(ip)
	if err != nil {
		return fmt.Errorf("internal: invalid stored IP %q: %w", ip, err)
	}

	ka := time.Duration(keepalive) * time.Second
	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   pubKey,
		UpdateOnly:                  true,
		AllowedIPs:                  []net.IPNet{*ipNet},
		PersistentKeepaliveInterval: &ka,
	}

	if err := m.client.ConfigureDevice(m.cfg.WGInterface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return fmt.Errorf("update peer: %w", err)
	}

	m.persistConfig()
	return nil
}

func (m *Manager) PeerStats(pubkeyStr string) (*PeerInfo, error) {
	dev, err := m.client.Device(m.cfg.WGInterface)
	if err != nil {
		return nil, err
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubkeyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	var pubKey wgtypes.Key
	copy(pubKey[:], pubKeyBytes)

	for _, peer := range dev.Peers {
		if peer.PublicKey == pubKey {
			info := &PeerInfo{
				PublicKey:     pubkeyStr,
				TransmitBytes: peer.TransmitBytes,
				ReceiveBytes:  peer.ReceiveBytes,
			}
			if !peer.LastHandshakeTime.IsZero() {
				hs := peer.LastHandshakeTime
				info.LastHandshake = &hs
			}
			if len(peer.AllowedIPs) > 0 {
				info.AllowedIP = peer.AllowedIPs[0].String()
			}
			if peer.Endpoint != nil {
				info.Endpoint = peer.Endpoint.String()
			}
			return info, nil
		}
	}

	return nil, errors.New("peer not found")
}

func (m *Manager) ListPeers() ([]PeerInfo, error) {
	dev, err := m.client.Device(m.cfg.WGInterface)
	if err != nil {
		return nil, err
	}

	peers := make([]PeerInfo, 0, len(dev.Peers))
	for _, peer := range dev.Peers {
		info := PeerInfo{
			PublicKey:     base64.StdEncoding.EncodeToString(peer.PublicKey[:]),
			TransmitBytes: peer.TransmitBytes,
			ReceiveBytes:  peer.ReceiveBytes,
		}
		if !peer.LastHandshakeTime.IsZero() {
			hs := peer.LastHandshakeTime
			info.LastHandshake = &hs
		}
		if len(peer.AllowedIPs) > 0 {
			info.AllowedIP = peer.AllowedIPs[0].String()
		}
		if peer.Endpoint != nil {
			info.Endpoint = peer.Endpoint.String()
		}
		peers = append(peers, info)
	}

	return peers, nil
}

func (m *Manager) ServerStats() (*ServerStatsResponse, error) {
	dev, err := m.client.Device(m.cfg.WGInterface)
	if err != nil {
		return nil, err
	}

	var totalTX, totalRX int64
	for _, peer := range dev.Peers {
		totalTX += peer.TransmitBytes
		totalRX += peer.ReceiveBytes
	}

	pubKey := base64.StdEncoding.EncodeToString(dev.PublicKey[:])

	return &ServerStatsResponse{
		Interface:  m.cfg.WGInterface,
		PublicKey:  pubKey,
		ListenPort: dev.ListenPort,
		PeerCount:  len(dev.Peers),
		TotalTX:    totalTX,
		TotalRX:    totalRX,
	}, nil
}

// --- Persistence ---

func (m *Manager) persistConfig() {
	confPath := filepath.Join(m.cfg.ConfigDir, m.cfg.WGInterface+".conf")

	if err := os.MkdirAll(m.cfg.ConfigDir, 0700); err != nil {
		slog.Error("error creating config dir", "error", err)
		return
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", base64.StdEncoding.EncodeToString(m.privateKey[:])))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", m.cfg.WGPort))
	sb.WriteString(fmt.Sprintf("Address = %s\n", m.pool.GatewayIP()))
	sb.WriteString("\n")

	dev, err := m.client.Device(m.cfg.WGInterface)
	if err != nil {
		slog.Error("error reading device for persistence", "error", err)
		return
	}

	for _, peer := range dev.Peers {
		sb.WriteString("[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", base64.StdEncoding.EncodeToString(peer.PublicKey[:])))
		for _, aip := range peer.AllowedIPs {
			sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", aip.String()))
		}
		if peer.PersistentKeepaliveInterval > 0 {
			sb.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", int(peer.PersistentKeepaliveInterval.Seconds())))
		}
		sb.WriteString("\n")
	}

	if err := os.WriteFile(confPath+".tmp", []byte(sb.String()), 0600); err != nil {
		slog.Error("error writing config", "error", err)
		return
	}
	if err := os.Rename(confPath+".tmp", confPath); err != nil {
		slog.Error("error renaming config", "error", err)
	} else {
		slog.Info("persisted config", "path", confPath)
	}
}

// meshIPNet is the overlay network range assigned to mesh networks (10.200.0.0/16).
// Used to distinguish mesh IPs from regular VPN pool IPs in AllowedIPs lists.
var meshIPNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("10.200.0.0/16")
	return n
}()

// AddMeshIP appends a mesh overlay IP (/32) to the peer's WireGuard AllowedIPs.
// It reads the peer's current VPN pool IP so that the combined list
// [vpnPoolIP/32, meshIP/32] is sent atomically to the kernel.
func (m *Manager) AddMeshIP(pubkeyStr, meshIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubkeyStr)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	var pubKey wgtypes.Key
	copy(pubKey[:], pubKeyBytes)

	vpnIP, ok := m.peerIPs[pubkeyStr]
	if !ok {
		return errors.New("peer not found")
	}

	_, vpnNet, err := net.ParseCIDR(vpnIP)
	if err != nil {
		return fmt.Errorf("internal: invalid VPN IP %q: %w", vpnIP, err)
	}

	meshIPParsed := net.ParseIP(meshIP)
	if meshIPParsed == nil {
		return fmt.Errorf("invalid mesh IP: %q", meshIP)
	}
	meshNet := &net.IPNet{IP: meshIPParsed.To4(), Mask: net.CIDRMask(32, 32)}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		UpdateOnly:        true,
		AllowedIPs:        []net.IPNet{*vpnNet, *meshNet},
		ReplaceAllowedIPs: true,
	}

	if err := m.client.ConfigureDevice(m.cfg.WGInterface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return fmt.Errorf("add mesh IP: %w", err)
	}

	m.meshIPs[pubkeyStr] = meshIP
	m.persistConfig()
	return nil
}

// RemoveMeshIP removes the mesh overlay IP from the peer's WireGuard AllowedIPs,
// leaving only the VPN pool IP in place.
func (m *Manager) RemoveMeshIP(pubkeyStr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.meshIPs[pubkeyStr]; !ok {
		// Nothing to do — peer has no mesh IP registered.
		return nil
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubkeyStr)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	var pubKey wgtypes.Key
	copy(pubKey[:], pubKeyBytes)

	vpnIP, ok := m.peerIPs[pubkeyStr]
	if !ok {
		return errors.New("peer not found")
	}

	_, vpnNet, err := net.ParseCIDR(vpnIP)
	if err != nil {
		return fmt.Errorf("internal: invalid VPN IP %q: %w", vpnIP, err)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		UpdateOnly:        true,
		AllowedIPs:        []net.IPNet{*vpnNet},
		ReplaceAllowedIPs: true,
	}

	if err := m.client.ConfigureDevice(m.cfg.WGInterface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return fmt.Errorf("remove mesh IP: %w", err)
	}

	delete(m.meshIPs, pubkeyStr)
	m.persistConfig()
	return nil
}

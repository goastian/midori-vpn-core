package wg

import (
	"encoding/base64"
	"encoding/json"
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
	"github.com/google/uuid"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	maxKeepaliveSeconds  = 65535
	operationStateSchema = 1
)

var (
	ErrInvalidPublicKey       = errors.New("public key must be canonical base64 encoding of exactly 32 bytes")
	ErrInvalidPresharedKey    = errors.New("preshared key must be canonical base64 encoding of exactly 32 bytes")
	ErrInvalidOperationID     = errors.New("operation_id must be a non-zero UUID")
	ErrInvalidKeepalive       = errors.New("keepalive is outside the supported range")
	ErrPeerOperationConflict  = errors.New("peer is owned by another operation")
	ErrPeerOperationUntracked = errors.New("peer operation identity is unavailable")
	ErrPeerStateUnavailable   = errors.New("WireGuard peer state is unavailable")
	ErrPeerCapacityReached    = errors.New("desired peer capacity is reached")
	ErrPeerCapacityBelowUsage = errors.New("desired peer capacity is below current usage")
)

type wireGuardClient interface {
	Device(string) (*wgtypes.Device, error)
	ConfigureDevice(string, wgtypes.Config) error
	Close() error
}

// commandRunner substitutes only the OS boundary in network/firewall tests.
type commandRunner func(name, stdin string, args ...string) ([]byte, error)

type PeerInfo struct {
	PublicKey     string     `json:"public_key"`
	OperationID   uuid.UUID  `json:"operation_id"`
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
	mu                 sync.Mutex
	cfg                *config.Config
	client             wireGuardClient
	pool               *ippool.Pool
	peerIPs            map[string]string // pubkey -> allocated VPN pool IP (e.g. "10.8.0.5/32")
	peerOps            map[string]uuid.UUID
	meshIPs            map[string]string // pubkey -> mesh overlay IP  (e.g. "10.200.1.2")
	peerStateAvailable bool
	peerLimit          int
	privateKey         wgtypes.Key
	runCommand         commandRunner
}

func (m *Manager) run(name, stdin string, args ...string) ([]byte, error) {
	if m.runCommand != nil {
		return m.runCommand(name, stdin, args...)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.CombinedOutput()
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
		cfg:       cfg,
		client:    client,
		pool:      pool,
		peerIPs:   make(map[string]string),
		peerOps:   make(map[string]uuid.UUID),
		meshIPs:   make(map[string]string),
		peerLimit: cfg.CoreNodeMaxPeers,
	}

	if err := m.ensureInterface(); err != nil {
		client.Close()
		return nil, err
	}

	if err := m.loadExistingPeers(); err != nil {
		slog.Warn("could not load existing peers", "error", err)
	} else if err := m.loadOperationState(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("load peer operation state: %w", err)
	} else {
		m.peerStateAvailable = true
	}

	return m, nil
}

// ApplyPeerLimit serializes a desired-state persistence callback with peer
// mutation, so the durable bundle and effective admission limit change as one
// local operation.
func (m *Manager) ApplyPeerLimit(limit int, commit func() error) error {
	if limit < 1 || limit > 65536 {
		return errors.New("peer limit must be between 1 and 65536")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.peerIPs) > limit {
		return ErrPeerCapacityBelowUsage
	}
	if commit != nil {
		if err := commit(); err != nil {
			return err
		}
	}
	m.peerLimit = limit
	return nil
}

func (m *Manager) Close() {
	_ = m.client.Close()
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

	// Protect an already-running interface before touching its key or peers.
	if err := m.ensureNATRules(); err != nil {
		return fmt.Errorf("ensureInterface: %w", err)
	}

	var zeroKey wgtypes.Key
	if dev.PrivateKey == zeroKey {
		slog.Info("existing interface has zero private key, generating new keypair", "interface", m.cfg.WGInterface)
		kp, err := crypto.GenerateKeypair()
		if err != nil {
			return fmt.Errorf("generate server keypair: %w", err)
		}
		privKeyBytes, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
		if err != nil {
			return err
		}
		copy(m.privateKey[:], privKeyBytes)
		port := m.cfg.WGPort
		wgCfg := wgtypes.Config{
			PrivateKey: &m.privateKey,
			ListenPort: &port,
		}
		if err := m.client.ConfigureDevice(m.cfg.WGInterface, wgCfg); err != nil {
			return fmt.Errorf("configure device %s: %w", m.cfg.WGInterface, err)
		}
		m.persistConfig()
	} else {
		m.privateKey = dev.PrivateKey
	}

	// A previous failed protection attempt may have deliberately left this
	// interface down. Re-enable it only after the isolation rules are in place.
	if out, err := m.run("ip", "", "link", "set", "up", "dev", m.cfg.WGInterface); err != nil {
		return fmt.Errorf("enable protected WireGuard interface %s: %w (output: %s)", m.cfg.WGInterface, err, strings.TrimSpace(string(out)))
	}

	pubKey := m.PublicKey()
	slog.Info("interface ready", "interface", m.cfg.WGInterface, "listen_port", m.cfg.WGPort, "peers", len(dev.Peers), "public_key", pubKey)
	return nil
}

func (m *Manager) createNetworkInterface() error {
	iface := m.cfg.WGInterface

	// Rules may match an absent interface. Install them before bringing it up,
	// including when restoring saved peers or falling back to API/Master mode.
	if err := m.ensureNATRules(); err != nil {
		return fmt.Errorf("createNetworkInterface: %w", err)
	}

	// Check if interface already exists on the system
	if _, err := m.run("ip", "", "link", "show", "dev", iface); err != nil {
		// Interface does not exist, attempt to load module if needed and create interface
		_, _ = m.run("modprobe", "", "wireguard")
		if out, err := m.run("ip", "", "link", "add", "dev", iface, "type", "wireguard"); err != nil {
			msg := strings.TrimSpace(string(out))
			if strings.Contains(msg, "Unknown device type") || strings.Contains(msg, "Operation not permitted") {
				slog.Warn("wireguard kernel device cannot be created in this container namespace; running in API/Master mode", "interface", iface, "detail", msg)
				return nil
			}
			return fmt.Errorf("ip link add %s: %s: %w", iface, msg, err)
		}
	}

	// Assign the gateway IP from the subnet to the interface
	gatewayIP := m.pool.GatewayIP()
	if out, err := m.run("ip", "", "address", "add", "dev", iface, gatewayIP); err != nil {
		msg := strings.TrimSpace(string(out))
		if !strings.Contains(msg, "File exists") && !strings.Contains(msg, "Operation not permitted") {
			return fmt.Errorf("ip address add %s: %s: %w", gatewayIP, msg, err)
		}
		slog.Info("interface address already configured or managed by host", "interface", iface, "address", gatewayIP)
	}

	// Bring the interface up (best-effort if already UP on host)
	if out, err := m.run("ip", "", "link", "set", "up", "dev", iface); err != nil {
		msg := strings.TrimSpace(string(out))
		if !strings.Contains(msg, "Operation not permitted") {
			return fmt.Errorf("ip link set up %s: %s: %w", iface, msg, err)
		}
	}

	slog.Info("created network interface", "interface", iface, "address", gatewayIP)
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
		slog.Warn("configure device failed; running in API/Master mode", "interface", m.cfg.WGInterface, "error", err)
	} else {
		m.persistConfig()
		slog.Info("configured interface", "interface", m.cfg.WGInterface, "port", port, "public_key", kp.PublicKey)
	}
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
		slog.Warn("restore: configure device failed; running in API/Master mode", "error", err)
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

func (m *Manager) loadExistingPeers() error {
	dev, err := m.client.Device(m.cfg.WGInterface)
	if err != nil {
		return fmt.Errorf("observe WireGuard device: %w", err)
	}

	for _, peer := range dev.Peers {
		pubkey := base64.StdEncoding.EncodeToString(peer.PublicKey[:])
		vpnAddresses := 0
		for _, aip := range peer.AllowedIPs {
			ip := aip.IP.String()
			if meshIPNet != nil && meshIPNet.Contains(aip.IP) {
				m.meshIPs[pubkey] = ip
			} else {
				ones, bits := aip.Mask.Size()
				if bits != 32 || ones != 32 || aip.IP.To4() == nil {
					return fmt.Errorf("peer %s has invalid VPN address %s", pubkey, aip.String())
				}
				vpnAddresses++
				if vpnAddresses > 1 {
					return fmt.Errorf("peer %s has multiple VPN pool addresses", pubkey)
				}
				m.peerIPs[pubkey] = ip + "/32"
				if err := m.pool.Reserve(ip); err != nil {
					return fmt.Errorf("reserve observed peer address %s: %w", ip, err)
				}
			}
		}
		if vpnAddresses != 1 {
			return fmt.Errorf("peer %s has no VPN pool address", pubkey)
		}
	}

	slog.Info("loaded existing peers", "count", len(dev.Peers), "interface", m.cfg.WGInterface)
	return nil
}

func decodeWireGuardKey(value string, invalidError error) (wgtypes.Key, error) {
	var key wgtypes.Key
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != len(key) || base64.StdEncoding.EncodeToString(raw) != value {
		return key, invalidError
	}
	copy(key[:], raw)
	return key, nil
}

func parseOperationID(value string) (uuid.UUID, error) {
	operationID, err := uuid.Parse(value)
	if err != nil || operationID == uuid.Nil {
		return uuid.Nil, ErrInvalidOperationID
	}
	return operationID, nil
}

// --- Public API ---

func (m *Manager) AddPeer(pubkeyStr, operationID string, keepalive int) (string, bool, error) {
	return m.AddPeerWithPSK(pubkeyStr, operationID, keepalive, "")
}

// AddPeerWithPSK applies one exact provisioning operation. Repeating the same
// operation for the same public key returns the original address without
// touching WireGuard. A key or operation already owned by another request is a
// conflict rather than an implicit replacement.
func (m *Manager) AddPeerWithPSK(pubkeyStr, operationID string, keepalive int, pskStr string) (string, bool, error) {
	pubKey, err := decodeWireGuardKey(pubkeyStr, ErrInvalidPublicKey)
	if err != nil {
		return "", false, err
	}
	opID, err := parseOperationID(operationID)
	if err != nil {
		return "", false, err
	}
	if keepalive < 1 || keepalive > maxKeepaliveSeconds {
		return "", false, ErrInvalidKeepalive
	}
	var presharedKey *wgtypes.Key
	if pskStr != "" {
		psk, err := decodeWireGuardKey(pskStr, ErrInvalidPresharedKey)
		if err != nil {
			return "", false, err
		}
		presharedKey = &psk
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.peerStateAvailable {
		return "", false, ErrPeerStateUnavailable
	}

	if existingIP, exists := m.peerIPs[pubkeyStr]; exists {
		if existingOperation, tracked := m.peerOps[pubkeyStr]; tracked && existingOperation == opID {
			return existingIP, false, nil
		}
		return "", false, ErrPeerOperationConflict
	}
	for existingKey, existingOperation := range m.peerOps {
		if existingKey != pubkeyStr && existingOperation == opID {
			return "", false, ErrPeerOperationConflict
		}
	}
	if m.peerLimit > 0 && len(m.peerIPs) >= m.peerLimit {
		return "", false, ErrPeerCapacityReached
	}

	allocatedIP, err := m.pool.Allocate()
	if err != nil {
		return "", false, fmt.Errorf("IP allocation: %w", err)
	}

	_, ipNet, err := net.ParseCIDR(allocatedIP)
	if err != nil {
		_ = m.pool.Release(allocatedIP)
		return "", false, fmt.Errorf("internal: invalid allocated IP %q: %w", allocatedIP, err)
	}

	ka := time.Duration(keepalive) * time.Second
	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   pubKey,
		AllowedIPs:                  []net.IPNet{*ipNet},
		PersistentKeepaliveInterval: &ka,
	}
	if presharedKey != nil {
		peerCfg.PresharedKey = presharedKey
	}

	m.peerIPs[pubkeyStr] = allocatedIP
	m.peerOps[pubkeyStr] = opID
	if err := m.persistOperationStateLocked(); err != nil {
		_ = m.pool.Release(allocatedIP)
		delete(m.peerIPs, pubkeyStr)
		delete(m.peerOps, pubkeyStr)
		return "", false, fmt.Errorf("persist peer operation: %w", err)
	}

	// Persist the ownership before changing WireGuard. This closes the crash
	// window where the kernel contained a peer whose original operation ID had
	// never reached durable storage. An entry without an observed kernel peer is
	// discarded safely during startup.
	if err := m.client.ConfigureDevice(m.cfg.WGInterface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		_ = m.pool.Release(allocatedIP)
		delete(m.peerIPs, pubkeyStr)
		delete(m.peerOps, pubkeyStr)
		if rollbackErr := m.persistOperationStateLocked(); rollbackErr != nil {
			m.peerStateAvailable = false
			return "", false, errors.Join(fmt.Errorf("configure peer: %w", err), fmt.Errorf("rollback peer operation: %w", rollbackErr))
		}
		return "", false, fmt.Errorf("configure peer: %w", err)
	}
	m.persistConfig()

	return allocatedIP, true, nil
}

func (m *Manager) RemovePeer(pubkeyStr, expectedOperationID string) error {
	pubKey, err := decodeWireGuardKey(pubkeyStr, ErrInvalidPublicKey)
	if err != nil {
		return err
	}
	expectedID, err := parseOperationID(expectedOperationID)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.peerStateAvailable {
		return ErrPeerStateUnavailable
	}

	ip, exists := m.peerIPs[pubkeyStr]
	if !exists {
		return nil
	}
	operationID, tracked := m.peerOps[pubkeyStr]
	if !tracked || operationID != expectedID {
		return ErrPeerOperationConflict
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	if err := m.client.ConfigureDevice(m.cfg.WGInterface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}

	_ = m.pool.Release(ip)
	delete(m.peerIPs, pubkeyStr)
	delete(m.peerOps, pubkeyStr)
	if err := m.persistOperationStateLocked(); err != nil {
		return fmt.Errorf("persist peer removal: %w", err)
	}

	m.persistConfig()
	return nil
}

func (m *Manager) UpdatePeer(pubkeyStr string, keepalive int) error {
	pubKey, err := decodeWireGuardKey(pubkeyStr, ErrInvalidPublicKey)
	if err != nil {
		return err
	}
	if keepalive < 0 || keepalive > maxKeepaliveSeconds {
		return ErrInvalidKeepalive
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.peerStateAvailable {
		return ErrPeerStateUnavailable
	}

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
	pubKey, err := decodeWireGuardKey(pubkeyStr, ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.peerStateAvailable {
		return nil, ErrPeerStateUnavailable
	}

	dev, err := m.client.Device(m.cfg.WGInterface)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPeerStateUnavailable, err)
	}

	for _, peer := range dev.Peers {
		if peer.PublicKey == pubKey {
			operationID, ok := m.peerOps[pubkeyStr]
			if !ok {
				return nil, ErrPeerOperationUntracked
			}
			info := &PeerInfo{
				PublicKey:     pubkeyStr,
				OperationID:   operationID,
				Keepalive:     int(peer.PersistentKeepaliveInterval / time.Second),
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.peerStateAvailable {
		return nil, ErrPeerStateUnavailable
	}

	dev, err := m.client.Device(m.cfg.WGInterface)
	if err != nil {
		return nil, err
	}

	peers := make([]PeerInfo, 0, len(dev.Peers))
	for _, peer := range dev.Peers {
		publicKey := base64.StdEncoding.EncodeToString(peer.PublicKey[:])
		operationID, ok := m.peerOps[publicKey]
		if !ok {
			return nil, ErrPeerOperationUntracked
		}
		info := PeerInfo{
			PublicKey:     publicKey,
			OperationID:   operationID,
			Keepalive:     int(peer.PersistentKeepaliveInterval / time.Second),
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

type peerOperationState struct {
	Schema int               `json:"schema"`
	Peers  map[string]string `json:"peers"`
}

func (m *Manager) operationStatePath() string {
	return filepath.Join(m.cfg.ConfigDir, m.cfg.WGInterface+".peer-operations.json")
}

// loadOperationState binds every observed peer to a stable operation UUID.
// Peers from pre-2.0 state receive a generated legacy owner exactly once and
// the result is persisted before the Core starts serving requests.
func (m *Manager) loadOperationState() error {
	state := peerOperationState{Schema: operationStateSchema, Peers: make(map[string]string)}
	statePath := m.operationStatePath()
	data, err := os.ReadFile(statePath)
	stateExists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", statePath, err)
	}
	if stateExists {
		if err := json.Unmarshal(data, &state); err != nil {
			return fmt.Errorf("decode %s: %w", statePath, err)
		}
		if state.Schema != operationStateSchema || state.Peers == nil {
			return fmt.Errorf("unsupported peer operation state schema %d", state.Schema)
		}
	}

	loaded := make(map[string]uuid.UUID, len(m.peerIPs))
	operationOwners := make(map[uuid.UUID]string, len(m.peerIPs))
	changed := len(state.Peers) != len(m.peerIPs)
	for publicKey, operationID := range state.Peers {
		if _, err := decodeWireGuardKey(publicKey, ErrInvalidPublicKey); err != nil {
			return fmt.Errorf("invalid persisted peer key: %w", err)
		}
		parsed, err := parseOperationID(operationID)
		if err != nil {
			return fmt.Errorf("invalid persisted operation for peer %s: %w", publicKey, err)
		}
		if _, observed := m.peerIPs[publicKey]; observed {
			if existingKey, duplicate := operationOwners[parsed]; duplicate && existingKey != publicKey {
				return fmt.Errorf("operation %s is assigned to multiple peers", parsed)
			}
			loaded[publicKey] = parsed
			operationOwners[parsed] = publicKey
		}
	}
	for publicKey := range m.peerIPs {
		if _, ok := loaded[publicKey]; !ok {
			loaded[publicKey] = uuid.New()
			changed = true
		}
	}
	m.peerOps = loaded
	if changed || (!stateExists && len(loaded) > 0) {
		if err := m.persistOperationStateLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) persistOperationStateLocked() error {
	if err := os.MkdirAll(m.cfg.ConfigDir, 0700); err != nil {
		return fmt.Errorf("create operation state directory: %w", err)
	}
	state := peerOperationState{Schema: operationStateSchema, Peers: make(map[string]string, len(m.peerOps))}
	for publicKey, operationID := range m.peerOps {
		state.Peers[publicKey] = operationID.String()
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode peer operation state: %w", err)
	}
	data = append(data, '\n')

	statePath := m.operationStatePath()
	temporaryPath := statePath + ".tmp"
	file, err := os.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open peer operation state: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return fmt.Errorf("protect peer operation state: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write peer operation state: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync peer operation state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close peer operation state: %w", err)
	}
	if err := os.Rename(temporaryPath, statePath); err != nil {
		return fmt.Errorf("activate peer operation state: %w", err)
	}
	removeTemporary = false
	directory, err := os.Open(m.cfg.ConfigDir)
	if err != nil {
		return fmt.Errorf("open operation state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync operation state directory: %w", err)
	}
	return nil
}

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

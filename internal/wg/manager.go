package wg

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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
	PublicKey       string    `json:"public_key"`
	AllowedIP      string    `json:"allowed_ip"`
	Keepalive      int       `json:"keepalive"`
	LastHandshake  time.Time `json:"last_handshake"`
	TransmitBytes  int64     `json:"tx_bytes"`
	ReceiveBytes   int64     `json:"rx_bytes"`
	Endpoint       string    `json:"endpoint,omitempty"`
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
	peerIPs    map[string]string // pubkey -> allocated IP
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
	}

	if err := m.ensureInterface(); err != nil {
		client.Close()
		return nil, err
	}

	if err := m.loadExistingPeers(); err != nil {
		log.Printf("warning: could not load existing peers: %v", err)
	}

	return m, nil
}

func (m *Manager) Close() {
	m.client.Close()
}

func (m *Manager) ensureInterface() error {
	dev, err := m.client.Device(m.cfg.WGInterface)
	if err != nil {
		log.Printf("interface %s not found, attempting to configure...", m.cfg.WGInterface)
		return m.configureNewInterface()
	}

	m.privateKey = dev.PrivateKey
	log.Printf("interface %s already exists, listen port %d, %d peers",
		m.cfg.WGInterface, dev.ListenPort, len(dev.Peers))
	return nil
}

func (m *Manager) configureNewInterface() error {
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
	log.Printf("configured interface %s on port %d", m.cfg.WGInterface, port)
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
			m.peerIPs[pubkey] = ip + "/32"
			_ = m.pool.Reserve(ip)
		}
	}

	log.Printf("loaded %d existing peers from interface %s", len(dev.Peers), m.cfg.WGInterface)
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

	_, ipNet, _ := net.ParseCIDR(allocatedIP)

	ka := time.Duration(keepalive) * time.Second
	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   pubKey,
		AllowedIPs:                 []net.IPNet{*ipNet},
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
		Remove:   true,
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

	_, ipNet, _ := net.ParseCIDR(ip)

	ka := time.Duration(keepalive) * time.Second
	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   pubKey,
		UpdateOnly:                 true,
		AllowedIPs:                 []net.IPNet{*ipNet},
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
				PublicKey:      pubkeyStr,
				LastHandshake:  peer.LastHandshakeTime,
				TransmitBytes:  peer.TransmitBytes,
				ReceiveBytes:   peer.ReceiveBytes,
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
			PublicKey:      base64.StdEncoding.EncodeToString(peer.PublicKey[:]),
			LastHandshake:  peer.LastHandshakeTime,
			TransmitBytes:  peer.TransmitBytes,
			ReceiveBytes:   peer.ReceiveBytes,
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
		log.Printf("error creating config dir: %v", err)
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
		log.Printf("error reading device for persistence: %v", err)
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

	if err := os.WriteFile(confPath, []byte(sb.String()), 0600); err != nil {
		log.Printf("error writing config: %v", err)
	} else {
		log.Printf("persisted config to %s", confPath)
	}
}

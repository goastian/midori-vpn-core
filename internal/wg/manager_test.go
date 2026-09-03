package wg

import (
	"encoding/base64"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/ippool"
)

type fakeWireGuardClient struct {
	device         wgtypes.Device
	deviceErr      error
	configureErr   error
	configureHook  func()
	configureCalls int
}

func (f *fakeWireGuardClient) Device(string) (*wgtypes.Device, error) {
	if f.deviceErr != nil {
		return nil, f.deviceErr
	}
	copy := f.device
	copy.Peers = append([]wgtypes.Peer(nil), f.device.Peers...)
	return &copy, nil
}

func (f *fakeWireGuardClient) ConfigureDevice(_ string, configuration wgtypes.Config) error {
	f.configureCalls++
	if f.configureHook != nil {
		f.configureHook()
	}
	if f.configureErr != nil {
		return f.configureErr
	}
	for _, requested := range configuration.Peers {
		index := -1
		for i := range f.device.Peers {
			if f.device.Peers[i].PublicKey == requested.PublicKey {
				index = i
				break
			}
		}
		if requested.Remove {
			if index >= 0 {
				f.device.Peers = append(f.device.Peers[:index], f.device.Peers[index+1:]...)
			}
			continue
		}
		if requested.UpdateOnly && index < 0 {
			return errors.New("peer not found")
		}
		peer := wgtypes.Peer{PublicKey: requested.PublicKey, AllowedIPs: requested.AllowedIPs}
		if requested.PersistentKeepaliveInterval != nil {
			peer.PersistentKeepaliveInterval = *requested.PersistentKeepaliveInterval
		}
		if index >= 0 {
			f.device.Peers[index] = peer
		} else {
			f.device.Peers = append(f.device.Peers, peer)
		}
	}
	return nil
}

func TestAddPersistsOperationBeforeChangingWireGuard(t *testing.T) {
	client := &fakeWireGuardClient{}
	manager := testManager(t, client)
	operationID := uuid.NewString()
	client.configureHook = func() {
		state, err := os.ReadFile(manager.operationStatePath())
		if err != nil {
			t.Errorf("operation state was not durable before WireGuard: %v", err)
			return
		}
		if !strings.Contains(string(state), `"`+operationID+`"`) {
			t.Errorf("operation state does not contain request operation: %s", state)
		}
	}
	if _, _, err := manager.AddPeer(testKey(7), operationID, 25); err != nil {
		t.Fatal(err)
	}
}

func TestAddRollsBackDurableOperationWhenWireGuardRejectsPeer(t *testing.T) {
	client := &fakeWireGuardClient{configureErr: errors.New("netlink rejected peer")}
	manager := testManager(t, client)
	operationID := uuid.NewString()
	publicKey := testKey(8)

	if _, _, err := manager.AddPeer(publicKey, operationID, 25); err == nil {
		t.Fatal("AddPeer error = nil")
	}
	state, err := os.ReadFile(manager.operationStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), operationID) || len(manager.peerOps) != 0 || len(manager.peerIPs) != 0 {
		t.Fatalf("failed add left operation state behind: %s", state)
	}
	if manager.pool.FreeCount() != 253 || !manager.peerStateAvailable {
		t.Fatalf("failed add did not restore manager: free=%d available=%v", manager.pool.FreeCount(), manager.peerStateAvailable)
	}
}

func (f *fakeWireGuardClient) Close() error { return nil }

func testKey(fill byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func testManager(t *testing.T, client wireGuardClient) *Manager {
	t.Helper()
	pool, err := ippool.New("10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{
		cfg: &config.Config{
			WGInterface: "wg-test",
			WGPort:      51820,
			Subnet:      "10.77.0.0/24",
			ConfigDir:   t.TempDir(),
		},
		client:             client,
		pool:               pool,
		peerIPs:            make(map[string]string),
		peerOps:            make(map[string]uuid.UUID),
		meshIPs:            make(map[string]string),
		peerStateAvailable: true,
	}
}

func TestPeerOperationsAreIdempotentAndConditional(t *testing.T) {
	client := &fakeWireGuardClient{}
	manager := testManager(t, client)
	publicKey := testKey(1)
	operationID := uuid.NewString()

	firstIP, created, err := manager.AddPeerWithPSK(publicKey, operationID, 25, testKey(2))
	if err != nil || !created {
		t.Fatalf("first add: ip=%q created=%v err=%v", firstIP, created, err)
	}
	configureCalls := client.configureCalls
	secondIP, created, err := manager.AddPeerWithPSK(publicKey, operationID, 25, testKey(2))
	if err != nil || created || secondIP != firstIP {
		t.Fatalf("idempotent add: ip=%q created=%v err=%v", secondIP, created, err)
	}
	if client.configureCalls != configureCalls {
		t.Fatal("idempotent retry changed WireGuard")
	}
	if _, _, err := manager.AddPeerWithPSK(publicKey, uuid.NewString(), 25, testKey(2)); !errors.Is(err, ErrPeerOperationConflict) {
		t.Fatalf("same key, other operation error = %v", err)
	}
	if _, _, err := manager.AddPeer(testKey(3), operationID, 25); !errors.Is(err, ErrPeerOperationConflict) {
		t.Fatalf("reused operation error = %v", err)
	}

	peers, err := manager.ListPeers()
	if err != nil || len(peers) != 1 || peers[0].OperationID.String() != operationID || peers[0].AllowedIP != firstIP {
		t.Fatalf("listed peers = %#v err=%v", peers, err)
	}
	if err := manager.RemovePeer(publicKey, uuid.NewString()); !errors.Is(err, ErrPeerOperationConflict) {
		t.Fatalf("mismatched remove error = %v", err)
	}
	if len(client.device.Peers) != 1 {
		t.Fatal("mismatched compensation removed the current peer")
	}
	if err := manager.RemovePeer(publicKey, operationID); err != nil {
		t.Fatalf("exact remove: %v", err)
	}
	if err := manager.RemovePeer(publicKey, operationID); err != nil {
		t.Fatalf("idempotent absent remove: %v", err)
	}
	if len(client.device.Peers) != 0 || manager.pool.FreeCount() != 253 {
		t.Fatalf("peer was not fully released: peers=%d free=%d", len(client.device.Peers), manager.pool.FreeCount())
	}
}

func TestDesiredPeerLimitIsAtomicAndPreservesIdempotentRetries(t *testing.T) {
	manager := testManager(t, &fakeWireGuardClient{})
	if err := manager.ApplyPeerLimit(1, nil); err != nil {
		t.Fatal(err)
	}
	publicKey := testKey(21)
	operationID := uuid.NewString()
	if _, created, err := manager.AddPeer(publicKey, operationID, 25); err != nil || !created {
		t.Fatalf("first peer: created=%v err=%v", created, err)
	}
	if _, created, err := manager.AddPeer(publicKey, operationID, 25); err != nil || created {
		t.Fatalf("idempotent retry at capacity: created=%v err=%v", created, err)
	}
	if _, _, err := manager.AddPeer(testKey(22), uuid.NewString(), 25); !errors.Is(err, ErrPeerCapacityReached) {
		t.Fatalf("capacity error = %v", err)
	}
	called := false
	if err := manager.ApplyPeerLimit(1, func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("atomic same limit: called=%v err=%v", called, err)
	}
	if err := manager.ApplyPeerLimit(0, func() error { t.Fatal("invalid limit committed"); return nil }); err == nil {
		t.Fatal("invalid peer limit accepted")
	}
}

func TestPeerMaterialAndKeepaliveValidation(t *testing.T) {
	client := &fakeWireGuardClient{}
	manager := testManager(t, client)
	operationID := uuid.NewString()
	validKey := testKey(4)

	tests := []struct {
		name      string
		publicKey string
		operation string
		keepalive int
		psk       string
		want      error
	}{
		{name: "short public key", publicKey: base64.StdEncoding.EncodeToString([]byte("short")), operation: operationID, keepalive: 25, want: ErrInvalidPublicKey},
		{name: "noncanonical public key", publicKey: base64.RawStdEncoding.EncodeToString(make([]byte, 32)), operation: operationID, keepalive: 25, want: ErrInvalidPublicKey},
		{name: "missing operation", publicKey: validKey, operation: "", keepalive: 25, want: ErrInvalidOperationID},
		{name: "zero operation", publicKey: validKey, operation: uuid.Nil.String(), keepalive: 25, want: ErrInvalidOperationID},
		{name: "negative keepalive", publicKey: validKey, operation: operationID, keepalive: -1, want: ErrInvalidKeepalive},
		{name: "oversized keepalive", publicKey: validKey, operation: operationID, keepalive: maxKeepaliveSeconds + 1, want: ErrInvalidKeepalive},
		{name: "short psk", publicKey: validKey, operation: operationID, keepalive: 25, psk: base64.StdEncoding.EncodeToString([]byte("short")), want: ErrInvalidPresharedKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := manager.AddPeerWithPSK(test.publicKey, test.operation, test.keepalive, test.psk); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	if client.configureCalls != 0 {
		t.Fatalf("invalid material reached WireGuard %d times", client.configureCalls)
	}
}

func TestLegacyPeerOperationPersistsAcrossReload(t *testing.T) {
	directory := t.TempDir()
	publicKeyText := testKey(5)
	publicKey, err := decodeWireGuardKey(publicKeyText, ErrInvalidPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, allowedIP, _ := net.ParseCIDR("10.77.0.9/32")
	client := &fakeWireGuardClient{device: wgtypes.Device{Peers: []wgtypes.Peer{{PublicKey: publicKey, AllowedIPs: []net.IPNet{*allowedIP}, PersistentKeepaliveInterval: 25 * time.Second}}}}

	newManager := func() *Manager {
		pool, poolErr := ippool.New("10.77.0.0/24")
		if poolErr != nil {
			t.Fatal(poolErr)
		}
		return &Manager{
			cfg:    &config.Config{WGInterface: "wg-test", WGPort: 51820, Subnet: "10.77.0.0/24", ConfigDir: directory},
			client: client, pool: pool, peerIPs: make(map[string]string), peerOps: make(map[string]uuid.UUID), meshIPs: make(map[string]string),
		}
	}

	first := newManager()
	if err := first.loadExistingPeers(); err != nil {
		t.Fatal(err)
	}
	if err := first.loadOperationState(); err != nil {
		t.Fatal(err)
	}
	operationID := first.peerOps[publicKeyText]
	if operationID == uuid.Nil {
		t.Fatal("legacy peer did not receive an operation identity")
	}
	info, err := os.Stat(first.operationStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("operation state permissions = %#o", info.Mode().Perm())
	}

	second := newManager()
	if err := second.loadExistingPeers(); err != nil {
		t.Fatal(err)
	}
	if err := second.loadOperationState(); err != nil {
		t.Fatal(err)
	}
	if second.peerOps[publicKeyText] != operationID {
		t.Fatalf("operation changed across reload: first=%s second=%s", operationID, second.peerOps[publicKeyText])
	}
}

func TestUnavailablePeerObservationFailsClosed(t *testing.T) {
	manager := testManager(t, &fakeWireGuardClient{deviceErr: errors.New("netlink unavailable")})
	manager.peerStateAvailable = false
	if _, _, err := manager.AddPeer(testKey(6), uuid.NewString(), 25); !errors.Is(err, ErrPeerStateUnavailable) {
		t.Fatalf("AddPeer error = %v", err)
	}
	if _, err := manager.ListPeers(); !errors.Is(err, ErrPeerStateUnavailable) {
		t.Fatalf("ListPeers error = %v", err)
	}
}

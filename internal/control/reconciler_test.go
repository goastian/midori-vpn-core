package control_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

type reconciliationFixture struct {
	pool     *pgxpool.Pool
	userID   uuid.UUID
	serverID uuid.UUID
	device   *models.Device
	cipher   *dataencryption.Cipher
}

func newReconciliationFixture(t *testing.T) reconciliationFixture {
	t.Helper()
	pool := handlerTestPool(t)
	ctx := context.Background()
	fixture := reconciliationFixture{pool: pool}
	fixture.cipher, _ = dataencryption.New([]byte("0123456789abcdef0123456789abcdef"))
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (authentik_uid, email, display_name)
		VALUES ($1, $2, 'Reconciliation Test User') RETURNING id`,
		uuid.NewString(), uuid.NewString()+"@test.invalid").Scan(&fixture.userID); err != nil {
		t.Fatalf("insert reconciliation user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO vpn_servers (name, host, max_peers, current_peers)
		VALUES ($1, 'reconciliation.test.invalid', 10, 0) RETURNING id`,
		"Reconciliation "+uuid.NewString()).Scan(&fixture.serverID); err != nil {
		t.Fatalf("insert reconciliation server: %v", err)
	}
	clientInstanceID := uuid.New()
	fixture.device = &models.Device{
		UserID: fixture.userID, ClientInstanceID: &clientInstanceID,
		ReportedName: "reconciliation-host", DeviceType: models.DeviceTypeDesktop,
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (user_id, client_instance_id, reported_name, device_type)
		VALUES ($1, $2, $3, $4) RETURNING id`, fixture.userID, clientInstanceID,
		fixture.device.ReportedName, fixture.device.DeviceType).Scan(&fixture.device.ID); err != nil {
		t.Fatalf("insert reconciliation device: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			UPDATE peer_operations SET state = 'failed', capacity_reserved = FALSE
			WHERE user_id = $1 AND state IN ('pending', 'core_applied', 'cleanup_pending')`, fixture.userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, fixture.userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id = $1`, fixture.serverID)
	})
	return fixture
}

func (f reconciliationFixture) begin(t *testing.T, fill byte) *repo.BeginConnectResult {
	t.Helper()
	result, err := repo.NewPeerOperationRepo(f.pool, f.cipher).BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID: uuid.New(), UserID: f.userID, Device: f.device,
		ServerID: f.serverID, PublicKey: connectOperationKey(fill),
		PresharedKey: connectOperationKey(fill + 100), MaxDevices: 1,
	})
	if err != nil {
		t.Fatalf("BeginConnect: %v", err)
	}
	return result
}

func (f reconciliationFixture) complete(t *testing.T, result *repo.BeginConnectResult, assignedIP string) (*models.Peer, *models.Peer) {
	t.Helper()
	operations := repo.NewPeerOperationRepo(f.pool, f.cipher)
	if err := operations.MarkCoreApplied(context.Background(), result.Operation.ID, assignedIP); err != nil {
		t.Fatalf("MarkCoreApplied: %v", err)
	}
	peer, previous, err := operations.CompleteConnect(context.Background(), result.Operation.ID)
	if err != nil {
		t.Fatalf("CompleteConnect: %v", err)
	}
	return peer, previous
}

func (f reconciliationFixture) makeStale(t *testing.T, operationID uuid.UUID) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE peer_operations SET updated_at = NOW() - INTERVAL '3 minutes'
		WHERE id = $1`, operationID); err != nil {
		t.Fatalf("age peer operation: %v", err)
	}
}

type fakeReconciliationCore struct {
	mu          sync.Mutex
	peers       map[uuid.UUID][]control.CorePeerStatsResponse
	listErrors  map[uuid.UUID]error
	managed     map[uuid.UUID]bool
	addCalls    int
	removeCalls []string
	removeError error
}

func newFakeReconciliationCore(serverID uuid.UUID) *fakeReconciliationCore {
	return &fakeReconciliationCore{
		peers:      make(map[uuid.UUID][]control.CorePeerStatsResponse),
		listErrors: make(map[uuid.UUID]error),
		managed:    map[uuid.UUID]bool{serverID: true},
	}
}

func (f *fakeReconciliationCore) ListPeers(_ context.Context, server *models.VPNServer) ([]control.CorePeerStatsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.listErrors[server.ID]; err != nil {
		return nil, err
	}
	if !f.managed[server.ID] {
		return nil, errors.New("server outside test fixture")
	}
	return append([]control.CorePeerStatsResponse(nil), f.peers[server.ID]...), nil
}

func (f *fakeReconciliationCore) AddPeer(_ context.Context, server *models.VPNServer, publicKey, operationID, _ string) (*control.CoreAddPeerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls++
	peer := control.CorePeerStatsResponse{
		PublicKey: publicKey, OperationID: operationID, AllowedIP: "10.99.0.2/32",
	}
	f.peers[server.ID] = append(f.peers[server.ID], peer)
	return &control.CoreAddPeerResponse{PublicKey: publicKey, OperationID: operationID, AllowedIP: peer.AllowedIP}, nil
}

func (f *fakeReconciliationCore) RemovePeer(_ context.Context, server *models.VPNServer, publicKey, operationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCalls = append(f.removeCalls, publicKey+"\x00"+operationID)
	if f.removeError != nil {
		return f.removeError
	}
	peers := f.peers[server.ID]
	for index, peer := range peers {
		if peer.PublicKey == publicKey && peer.OperationID == operationID {
			f.peers[server.ID] = append(peers[:index], peers[index+1:]...)
			break
		}
	}
	return nil
}

func TestReconcilerRecoversStalePendingOperation(t *testing.T) {
	fixture := newReconciliationFixture(t)
	pending := fixture.begin(t, 11)
	fixture.makeStale(t, pending.Operation.ID)
	core := newFakeReconciliationCore(fixture.serverID)

	report := control.NewReconciler(fixture.pool, core, fixture.cipher).RunOnce(context.Background())

	var state models.PeerOperationState
	var activePeers, currentPeers, attempts int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT operation.state, operation.attempts,
		       (SELECT COUNT(*) FROM peers WHERE provision_operation_id = operation.id AND is_active),
		       server.current_peers
		FROM peer_operations operation
		JOIN vpn_servers server ON server.id = operation.server_id
		WHERE operation.id = $1`, pending.Operation.ID).Scan(&state, &attempts, &activePeers, &currentPeers); err != nil {
		t.Fatalf("load recovered operation: %v", err)
	}
	if state != models.PeerOperationCompleted || attempts != 2 || activePeers != 1 || currentPeers != 1 || core.addCalls != 1 {
		t.Fatalf("recovery mismatch: state=%s attempts=%d active=%d current=%d adds=%d", state, attempts, activePeers, currentPeers, core.addCalls)
	}
	if report.PendingOperations != 0 {
		t.Fatalf("unexpected recovery report: %#v", report)
	}
}

func TestReconcilerCompletesAlreadyAppliedOperationWithoutAdding(t *testing.T) {
	fixture := newReconciliationFixture(t)
	pending := fixture.begin(t, 12)
	fixture.makeStale(t, pending.Operation.ID)
	core := newFakeReconciliationCore(fixture.serverID)
	core.peers[fixture.serverID] = []control.CorePeerStatsResponse{{
		PublicKey: pending.Operation.PublicKey, OperationID: pending.Operation.ID.String(), AllowedIP: "10.99.0.12/32",
	}}

	control.NewReconciler(fixture.pool, core, fixture.cipher).RunOnce(context.Background())

	var state models.PeerOperationState
	if err := fixture.pool.QueryRow(context.Background(), `SELECT state FROM peer_operations WHERE id = $1`, pending.Operation.ID).Scan(&state); err != nil {
		t.Fatalf("load already-applied operation: %v", err)
	}
	if state != models.PeerOperationCompleted || core.addCalls != 0 {
		t.Fatalf("already-applied recovery state=%s adds=%d", state, core.addCalls)
	}
}

func TestReconcilerPreservesDatabaseStateWhenCoreObservationFails(t *testing.T) {
	fixture := newReconciliationFixture(t)
	completed := fixture.begin(t, 13)
	peer, _ := fixture.complete(t, completed, "10.99.0.13/32")
	core := newFakeReconciliationCore(fixture.serverID)
	core.listErrors[fixture.serverID] = errors.New("Core unavailable")

	report := control.NewReconciler(fixture.pool, core, fixture.cipher).RunOnce(context.Background())

	var active bool
	var currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT peer.is_active, server.current_peers
		FROM peers peer JOIN vpn_servers server ON server.id = peer.server_id
		WHERE peer.id = $1`, peer.ID).Scan(&active, &currentPeers); err != nil {
		t.Fatalf("load peer after failed observation: %v", err)
	}
	if !active || currentPeers != 1 || report.ObservationErrors == 0 {
		t.Fatalf("failed observation mutated state: active=%t current=%d report=%#v", active, currentPeers, report)
	}
}

func TestReconcilerDeactivatesAbsentPeerAndRemovesExactOrphan(t *testing.T) {
	fixture := newReconciliationFixture(t)
	completed := fixture.begin(t, 14)
	peer, _ := fixture.complete(t, completed, "10.99.0.14/32")
	orphanKey := connectOperationKey(15)
	orphanOperation := uuid.NewString()
	core := newFakeReconciliationCore(fixture.serverID)
	core.peers[fixture.serverID] = []control.CorePeerStatsResponse{{
		PublicKey: orphanKey, OperationID: orphanOperation, AllowedIP: "10.99.0.15/32",
	}}

	report := control.NewReconciler(fixture.pool, core, fixture.cipher).RunOnce(context.Background())

	var active bool
	var currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT peer.is_active, server.current_peers
		FROM peers peer JOIN vpn_servers server ON server.id = peer.server_id
		WHERE peer.id = $1`, peer.ID).Scan(&active, &currentPeers); err != nil {
		t.Fatalf("load divergent peer: %v", err)
	}
	if active || currentPeers != 0 || report.DivergentPeers != 2 || report.OrphansRemoved != 1 {
		t.Fatalf("divergence did not converge: active=%t current=%d report=%#v", active, currentPeers, report)
	}
	if len(core.removeCalls) != 1 || core.removeCalls[0] != orphanKey+"\x00"+orphanOperation {
		t.Fatalf("orphan cleanup did not use exact owner: %#v", core.removeCalls)
	}
}

func TestReconcilerCompletesPendingPreviousPeerCleanup(t *testing.T) {
	fixture := newReconciliationFixture(t)
	first := fixture.begin(t, 16)
	firstPeer, _ := fixture.complete(t, first, "10.99.0.16/32")
	replacement := fixture.begin(t, 17)
	newPeer, previousPeer := fixture.complete(t, replacement, "10.99.0.17/32")
	if previousPeer == nil || previousPeer.ID != firstPeer.ID {
		t.Fatalf("replacement did not return previous peer: %#v", previousPeer)
	}
	fixture.makeStale(t, replacement.Operation.ID)
	core := newFakeReconciliationCore(fixture.serverID)
	core.peers[fixture.serverID] = []control.CorePeerStatsResponse{
		{PublicKey: firstPeer.PublicKey, OperationID: first.Operation.ID.String(), AllowedIP: firstPeer.AssignedIP},
		{PublicKey: newPeer.PublicKey, OperationID: replacement.Operation.ID.String(), AllowedIP: newPeer.AssignedIP},
	}

	report := control.NewReconciler(fixture.pool, core, fixture.cipher).RunOnce(context.Background())

	var state models.PeerOperationState
	if err := fixture.pool.QueryRow(context.Background(), `SELECT state FROM peer_operations WHERE id = $1`, replacement.Operation.ID).Scan(&state); err != nil {
		t.Fatalf("load cleanup operation: %v", err)
	}
	if state != models.PeerOperationCompleted || report.CleanupPending != 0 || len(core.removeCalls) != 1 {
		t.Fatalf("cleanup did not converge: state=%s report=%#v removals=%#v", state, report, core.removeCalls)
	}
}

func TestReconcilerDoesNotDuplicateFailedDurableCleanupAsOrphan(t *testing.T) {
	fixture := newReconciliationFixture(t)
	first := fixture.begin(t, 19)
	firstPeer, _ := fixture.complete(t, first, "10.99.0.19/32")
	replacement := fixture.begin(t, 20)
	newPeer, _ := fixture.complete(t, replacement, "10.99.0.20/32")
	fixture.makeStale(t, replacement.Operation.ID)
	core := newFakeReconciliationCore(fixture.serverID)
	core.removeError = errors.New("temporary Core cleanup failure")
	core.peers[fixture.serverID] = []control.CorePeerStatsResponse{
		{PublicKey: firstPeer.PublicKey, OperationID: first.Operation.ID.String(), AllowedIP: firstPeer.AssignedIP},
		{PublicKey: newPeer.PublicKey, OperationID: replacement.Operation.ID.String(), AllowedIP: newPeer.AssignedIP},
	}

	report := control.NewReconciler(fixture.pool, core, fixture.cipher).RunOnce(context.Background())

	var state models.PeerOperationState
	if err := fixture.pool.QueryRow(context.Background(), `SELECT state FROM peer_operations WHERE id = $1`, replacement.Operation.ID).Scan(&state); err != nil {
		t.Fatalf("load failed cleanup operation: %v", err)
	}
	if state != models.PeerOperationCleanupPending || report.CleanupPending != 1 || len(core.removeCalls) != 1 {
		t.Fatalf("durable cleanup was duplicated: state=%s report=%#v removals=%#v", state, report, core.removeCalls)
	}
}

func TestReconcileServerProtectsPeerCommittedAfterObservationStarted(t *testing.T) {
	fixture := newReconciliationFixture(t)
	pending := fixture.begin(t, 18)
	observationStartedAt := time.Now()
	time.Sleep(time.Millisecond)
	peer, _ := fixture.complete(t, pending, "10.99.0.18/32")

	result, err := repo.NewPeerRepo(fixture.pool).ReconcileServer(
		context.Background(), fixture.serverID, observationStartedAt, nil)
	if err != nil {
		t.Fatalf("ReconcileServer: %v", err)
	}
	if result.DeactivatedPeers != 0 || len(result.ActivePeers) != 1 || result.ActivePeers[0].ID != peer.ID {
		t.Fatalf("new concurrent peer was not protected: %#v", result)
	}
}

func TestReconcilerCompletesDurableDisconnectWithExactOwner(t *testing.T) {
	fixture := newReconciliationFixture(t)
	connected := fixture.begin(t, 74)
	peer, _ := fixture.complete(t, connected, "10.99.0.74/32")
	operations := repo.NewPeerOperationRepo(fixture.pool, fixture.cipher)
	disconnect, err := operations.BeginDisconnect(context.Background(), peer.ID)
	if err != nil {
		t.Fatalf("BeginDisconnect: %v", err)
	}
	fixture.makeStale(t, disconnect.Operation.ID)
	core := newFakeReconciliationCore(fixture.serverID)
	core.peers[fixture.serverID] = []control.CorePeerStatsResponse{{
		PublicKey: peer.PublicKey, OperationID: connected.Operation.ID.String(), AllowedIP: peer.AssignedIP,
	}}

	report := control.NewReconciler(fixture.pool, core, fixture.cipher).RunOnce(context.Background())

	var state models.PeerOperationState
	var active bool
	var currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT operation.state, peer.is_active, server.current_peers
		FROM peer_operations operation
		JOIN peers peer ON peer.id = operation.previous_peer_id
		JOIN vpn_servers server ON server.id = peer.server_id
		WHERE operation.id = $1`, disconnect.Operation.ID).Scan(&state, &active, &currentPeers); err != nil {
		t.Fatalf("load reconciled disconnect: %v", err)
	}
	wantRemoval := peer.PublicKey + "\x00" + connected.Operation.ID.String()
	if state != models.PeerOperationCompleted || active || currentPeers != 0 ||
		len(core.removeCalls) != 1 || core.removeCalls[0] != wantRemoval || report.PendingOperations != 0 {
		t.Fatalf("disconnect recovery mismatch: state=%s active=%t current=%d removals=%#v report=%#v",
			state, active, currentPeers, core.removeCalls, report)
	}
}

func TestReconcilerCancelsCoreAppliedConnectAfterBan(t *testing.T) {
	fixture := newReconciliationFixture(t)
	pending := fixture.begin(t, 75)
	if err := repo.NewPeerOperationRepo(fixture.pool, fixture.cipher).MarkCoreApplied(context.Background(), pending.Operation.ID, "10.99.0.75/32"); err != nil {
		t.Fatalf("MarkCoreApplied: %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE users SET is_banned = TRUE, banned_at = NOW() WHERE id = $1`, fixture.userID); err != nil {
		t.Fatalf("ban fixture user: %v", err)
	}
	fixture.makeStale(t, pending.Operation.ID)
	core := newFakeReconciliationCore(fixture.serverID)
	core.peers[fixture.serverID] = []control.CorePeerStatsResponse{{
		PublicKey: pending.Operation.PublicKey, OperationID: pending.Operation.ID.String(), AllowedIP: "10.99.0.75/32",
	}}

	control.NewReconciler(fixture.pool, core, fixture.cipher).RunOnce(context.Background())

	var state models.PeerOperationState
	var currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT operation.state, server.current_peers
		FROM peer_operations operation
		JOIN vpn_servers server ON server.id = operation.server_id
		WHERE operation.id = $1`, pending.Operation.ID).Scan(&state, &currentPeers); err != nil {
		t.Fatalf("load denied operation: %v", err)
	}
	if state != models.PeerOperationFailed || currentPeers != 0 || len(core.removeCalls) != 1 {
		t.Fatalf("denied connect did not converge: state=%s current=%d removals=%#v", state, currentPeers, core.removeCalls)
	}
}

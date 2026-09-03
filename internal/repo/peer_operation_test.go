package repo_test

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

type peerOperationFixture struct {
	pool     *pgxpool.Pool
	userID   uuid.UUID
	serverID uuid.UUID
	deviceID uuid.UUID
	device   *models.Device
}

func newPeerOperationFixture(t *testing.T, maxPeers int) peerOperationFixture {
	t.Helper()
	pool := testPool(t)
	ctx := context.Background()

	var fixture peerOperationFixture
	fixture.pool = pool
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (authentik_uid, email, display_name)
		VALUES ($1, $2, 'Operation Test User')
		RETURNING id`, uuid.NewString(), uuid.NewString()+"@test.invalid").Scan(&fixture.userID); err != nil {
		t.Fatalf("insert operation user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO vpn_servers (name, host, max_peers, current_peers)
		VALUES ($1, 'operation.test.invalid', $2, 0)
		RETURNING id`, "Operation "+uuid.NewString(), maxPeers).Scan(&fixture.serverID); err != nil {
		t.Fatalf("insert operation server: %v", err)
	}
	clientInstanceID := uuid.New()
	fixture.device = &models.Device{
		UserID:           fixture.userID,
		ClientInstanceID: &clientInstanceID,
		ReportedName:     "operation-host",
		DeviceType:       models.DeviceTypeDesktop,
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (user_id, client_instance_id, reported_name, device_type)
		VALUES ($1, $2, $3, $4)
		RETURNING id`, fixture.userID, clientInstanceID, fixture.device.ReportedName,
		fixture.device.DeviceType).Scan(&fixture.deviceID); err != nil {
		t.Fatalf("insert operation device: %v", err)
	}
	fixture.device.ID = fixture.deviceID

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			UPDATE peer_operations
			SET state = 'failed', capacity_reserved = FALSE
			WHERE user_id = $1 AND state IN ('pending', 'core_applied', 'cleanup_pending')`, fixture.userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, fixture.userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id = $1`, fixture.serverID)
	})
	return fixture
}

func operationKey(fill byte) string {
	key := make([]byte, 32)
	for index := range key {
		key[index] = fill
	}
	return base64.StdEncoding.EncodeToString(key)
}

func beginFixtureConnect(t *testing.T, fixture peerOperationFixture, operationRepo *repo.PeerOperationRepo, key string) *repo.BeginConnectResult {
	t.Helper()
	result, err := operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID:  uuid.New(),
		UserID:       fixture.userID,
		Device:       fixture.device,
		ServerID:     fixture.serverID,
		PublicKey:    key,
		PresharedKey: operationKey(200),
		MaxDevices:   1,
	})
	if err != nil {
		t.Fatalf("BeginConnect: %v", err)
	}
	return result
}

func completeFixtureConnect(t *testing.T, operationRepo *repo.PeerOperationRepo, operationID uuid.UUID, assignedIP string) (*models.Peer, *models.Peer) {
	t.Helper()
	if err := operationRepo.MarkCoreApplied(context.Background(), operationID, assignedIP); err != nil {
		t.Fatalf("MarkCoreApplied: %v", err)
	}
	peer, previousPeer, err := operationRepo.CompleteConnect(context.Background(), operationID)
	if err != nil {
		t.Fatalf("CompleteConnect: %v", err)
	}
	return peer, previousPeer
}

func TestPeerOperationConnectPersistsAndRetriesExactly(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := repo.NewPeerOperationRepo(fixture.pool)
	key := operationKey(1)
	result := beginFixtureConnect(t, fixture, operationRepo, key)

	var currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT current_peers FROM vpn_servers WHERE id = $1`, fixture.serverID).Scan(&currentPeers); err != nil {
		t.Fatalf("load reserved capacity: %v", err)
	}
	if currentPeers != 1 || !result.Operation.CapacityReserved || result.Operation.State != models.PeerOperationPending {
		t.Fatalf("unexpected pending reservation: peers=%d operation=%#v", currentPeers, result.Operation)
	}

	pending, pendingPeer, err := operationRepo.FindCurrentByKey(context.Background(), fixture.userID, key)
	if err != nil {
		t.Fatalf("FindCurrentByKey pending: %v", err)
	}
	if pending.ID != result.Operation.ID || pendingPeer != nil {
		t.Fatalf("pending retry mismatch: operation=%#v peer=%#v", pending, pendingPeer)
	}

	peer, previousPeer := completeFixtureConnect(t, operationRepo, result.Operation.ID, "10.90.0.2/32")
	if previousPeer != nil || peer.ProvisionOperationID == nil || *peer.ProvisionOperationID != result.Operation.ID {
		t.Fatalf("completed peer does not retain operation ownership: peer=%#v previous=%#v", peer, previousPeer)
	}

	completed, retryPeer, err := operationRepo.FindCurrentByKey(context.Background(), fixture.userID, key)
	if err != nil {
		t.Fatalf("FindCurrentByKey completed: %v", err)
	}
	if completed.State != models.PeerOperationCompleted || retryPeer == nil || retryPeer.ID != peer.ID {
		t.Fatalf("completed retry mismatch: operation=%#v peer=%#v", completed, retryPeer)
	}
	transactionalRetry, err := operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID: uuid.New(), UserID: fixture.userID, Device: fixture.device,
		ServerID: fixture.serverID, PublicKey: key, MaxDevices: 1,
	})
	if err != nil || transactionalRetry.ExistingPeer == nil || transactionalRetry.ExistingPeer.ID != peer.ID || transactionalRetry.Operation == nil || transactionalRetry.Operation.ID != completed.ID {
		t.Fatalf("transactional completed retry mismatch: result=%#v err=%v", transactionalRetry, err)
	}
	repeatedPeer, _, err := operationRepo.CompleteConnect(context.Background(), result.Operation.ID)
	if err != nil || repeatedPeer.ID != peer.ID {
		t.Fatalf("idempotent completion: peer=%#v err=%v", repeatedPeer, err)
	}
}

func TestPeerOperationReplacementWorksAtQuotaAndCapacityLimit(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := repo.NewPeerOperationRepo(fixture.pool)
	first := beginFixtureConnect(t, fixture, operationRepo, operationKey(2))
	firstPeer, _ := completeFixtureConnect(t, operationRepo, first.Operation.ID, "10.90.0.3/32")

	second := beginFixtureConnect(t, fixture, operationRepo, operationKey(3))
	if second.Operation.Action != models.PeerOperationReplace || second.Operation.CapacityReserved {
		t.Fatalf("same-server replacement reserved a second slot: %#v", second.Operation)
	}
	if second.Operation.PreviousOperationID == nil || *second.Operation.PreviousOperationID != first.Operation.ID {
		t.Fatalf("replacement did not persist the exact previous operation: %#v", second.Operation)
	}
	secondPeer, previousPeer := completeFixtureConnect(t, operationRepo, second.Operation.ID, "10.90.0.4/32")
	if previousPeer == nil || previousPeer.ID != firstPeer.ID || !previousPeer.IsActive {
		t.Fatalf("replacement lost exact previous peer: %#v", previousPeer)
	}
	if secondPeer.ID == firstPeer.ID {
		t.Fatal("replacement reused the historical peer row")
	}

	var activePeers, currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FILTER (WHERE peer.is_active), MAX(server.current_peers)
		FROM peers peer JOIN vpn_servers server ON server.id = peer.server_id
		WHERE peer.device_id = $1`, fixture.deviceID).Scan(&activePeers, &currentPeers); err != nil {
		t.Fatalf("load replacement counters: %v", err)
	}
	if activePeers != 1 || currentPeers != 1 {
		t.Fatalf("replacement counters diverged: active=%d current=%d", activePeers, currentPeers)
	}
}

func TestPeerOperationPersistsObservedLegacyOwner(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := repo.NewPeerOperationRepo(fixture.pool)
	if _, err := fixture.pool.Exec(context.Background(), `
		INSERT INTO peers (
			user_id, server_id, public_key, assigned_ip, device_name, device_id
		) VALUES ($1, $2, $3, '10.90.0.50/32', $4, $5)`,
		fixture.userID, fixture.serverID, operationKey(50), fixture.device.ReportedName, fixture.deviceID); err != nil {
		t.Fatalf("insert legacy peer: %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE vpn_servers SET current_peers = 1 WHERE id = $1`, fixture.serverID); err != nil {
		t.Fatalf("set legacy server capacity: %v", err)
	}

	replacement := beginFixtureConnect(t, fixture, operationRepo, operationKey(51))
	if replacement.Operation.PreviousOperationID != nil {
		t.Fatalf("legacy replacement unexpectedly had an owner: %#v", replacement.Operation)
	}
	observedOwner := uuid.New()
	if err := operationRepo.SetPreviousOperationID(context.Background(), replacement.Operation.ID, observedOwner); err != nil {
		t.Fatalf("SetPreviousOperationID: %v", err)
	}
	var persistedOwner uuid.UUID
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT previous_operation_id FROM peer_operations WHERE id = $1`, replacement.Operation.ID).Scan(&persistedOwner); err != nil {
		t.Fatalf("load previous operation owner: %v", err)
	}
	if persistedOwner != observedOwner {
		t.Fatalf("previous operation owner = %s, want %s", persistedOwner, observedOwner)
	}
	if err := operationRepo.FailDefinitively(context.Background(), replacement.Operation.ID, errors.New("test cleanup")); err != nil {
		t.Fatalf("release legacy replacement: %v", err)
	}
}

func TestPeerOperationCrossServerReplacementMovesCapacityAtomically(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := repo.NewPeerOperationRepo(fixture.pool)
	first := beginFixtureConnect(t, fixture, operationRepo, operationKey(30))
	completeFixtureConnect(t, operationRepo, first.Operation.ID, "10.90.0.30/32")

	var targetServerID uuid.UUID
	if err := fixture.pool.QueryRow(context.Background(), `
		INSERT INTO vpn_servers (name, host, max_peers, current_peers)
		VALUES ($1, 'replacement-target.test.invalid', 1, 0)
		RETURNING id`, "Replacement "+uuid.NewString()).Scan(&targetServerID); err != nil {
		t.Fatalf("insert replacement target: %v", err)
	}
	t.Cleanup(func() {
		_, _ = fixture.pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id = $1`, targetServerID)
	})

	replacement, err := operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID: uuid.New(), UserID: fixture.userID, Device: fixture.device,
		ServerID: targetServerID, PublicKey: operationKey(31), MaxDevices: 1,
	})
	if err != nil {
		t.Fatalf("BeginConnect cross-server: %v", err)
	}
	if replacement.Operation.Action != models.PeerOperationReplace || !replacement.Operation.CapacityReserved {
		t.Fatalf("cross-server operation did not reserve target: %#v", replacement.Operation)
	}
	_, previousPeer := completeFixtureConnect(t, operationRepo, replacement.Operation.ID, "10.91.0.2/32")
	if previousPeer == nil || previousPeer.ServerID != fixture.serverID {
		t.Fatalf("cross-server replacement lost source peer: %#v", previousPeer)
	}

	var sourcePeers, targetPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT
			(SELECT current_peers FROM vpn_servers WHERE id = $1),
			(SELECT current_peers FROM vpn_servers WHERE id = $2)`,
		fixture.serverID, targetServerID).Scan(&sourcePeers, &targetPeers); err != nil {
		t.Fatalf("load cross-server counters: %v", err)
	}
	if sourcePeers != 0 || targetPeers != 1 {
		t.Fatalf("cross-server counters diverged: source=%d target=%d", sourcePeers, targetPeers)
	}
}

func TestPeerOperationDefinitiveFailureReleasesReservation(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := repo.NewPeerOperationRepo(fixture.pool)
	result := beginFixtureConnect(t, fixture, operationRepo, operationKey(4))
	if err := operationRepo.FailDefinitively(context.Background(), result.Operation.ID, errors.New("Core rejected key")); err != nil {
		t.Fatalf("FailDefinitively: %v", err)
	}

	var state models.PeerOperationState
	var reserved bool
	var currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT operation.state, operation.capacity_reserved, server.current_peers
		FROM peer_operations operation
		JOIN vpn_servers server ON server.id = operation.server_id
		WHERE operation.id = $1`, result.Operation.ID).Scan(&state, &reserved, &currentPeers); err != nil {
		t.Fatalf("load failed operation: %v", err)
	}
	if state != models.PeerOperationFailed || reserved || currentPeers != 0 {
		t.Fatalf("failed operation leaked reservation: state=%s reserved=%t peers=%d", state, reserved, currentPeers)
	}
}

func TestPeerOperationPendingReservationCountsTowardDeviceQuota(t *testing.T) {
	fixture := newPeerOperationFixture(t, 2)
	operationRepo := repo.NewPeerOperationRepo(fixture.pool)
	pending := beginFixtureConnect(t, fixture, operationRepo, operationKey(40))

	otherInstanceID := uuid.New()
	otherDevice := &models.Device{UserID: fixture.userID, ClientInstanceID: &otherInstanceID, ReportedName: "quota-pending-host", DeviceType: models.DeviceTypeDesktop}
	if err := fixture.pool.QueryRow(context.Background(), `
		INSERT INTO devices (user_id, client_instance_id, reported_name, device_type)
		VALUES ($1, $2, $3, $4) RETURNING id`, fixture.userID, otherInstanceID,
		otherDevice.ReportedName, otherDevice.DeviceType).Scan(&otherDevice.ID); err != nil {
		t.Fatalf("insert pending quota device: %v", err)
	}

	_, err := operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID: uuid.New(), UserID: fixture.userID, Device: otherDevice,
		ServerID: fixture.serverID, PublicKey: operationKey(41), MaxDevices: 1,
	})
	if !errors.Is(err, repo.ErrDeviceLimitReached) {
		t.Fatalf("pending quota error = %v; want ErrDeviceLimitReached", err)
	}
	if err := operationRepo.FailDefinitively(context.Background(), pending.Operation.ID, errors.New("test cleanup")); err != nil {
		t.Fatalf("release pending quota reservation: %v", err)
	}
}

func TestPeerOperationConcurrentDeviceRequestsHaveOneWinner(t *testing.T) {
	fixture := newPeerOperationFixture(t, 2)
	operationRepo := repo.NewPeerOperationRepo(fixture.pool)

	results := make([]*repo.BeginConnectResult, 2)
	errorsSeen := make([]error, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	for index := 0; index < 2; index++ {
		index := index
		go func() {
			defer wait.Done()
			results[index], errorsSeen[index] = operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
				OperationID:  uuid.New(),
				UserID:       fixture.userID,
				Device:       fixture.device,
				ServerID:     fixture.serverID,
				PublicKey:    operationKey(byte(10 + index)),
				PresharedKey: operationKey(201),
				MaxDevices:   1,
			})
		}()
	}
	wait.Wait()

	winners := 0
	blocked := 0
	for index, err := range errorsSeen {
		switch {
		case err == nil:
			winners++
			if failErr := operationRepo.FailDefinitively(context.Background(), results[index].Operation.ID, errors.New("test cleanup")); failErr != nil {
				t.Fatalf("release winning operation: %v", failErr)
			}
		case errors.Is(err, repo.ErrConnectionInProgress):
			blocked++
		default:
			t.Fatalf("unexpected concurrent result %d: %v", index, err)
		}
	}
	if winners != 1 || blocked != 1 {
		t.Fatalf("concurrent outcomes: winners=%d blocked=%d errors=%v", winners, blocked, errorsSeen)
	}
}

func TestPeerOperationRechecksQuotaBeforeCapacity(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := repo.NewPeerOperationRepo(fixture.pool)
	first := beginFixtureConnect(t, fixture, operationRepo, operationKey(20))
	completeFixtureConnect(t, operationRepo, first.Operation.ID, "10.90.0.20/32")

	otherInstanceID := uuid.New()
	otherDevice := &models.Device{UserID: fixture.userID, ClientInstanceID: &otherInstanceID, ReportedName: "other-host", DeviceType: models.DeviceTypeDesktop}
	if err := fixture.pool.QueryRow(context.Background(), `
		INSERT INTO devices (user_id, client_instance_id, reported_name, device_type)
		VALUES ($1, $2, $3, $4) RETURNING id`, fixture.userID, otherInstanceID,
		otherDevice.ReportedName, otherDevice.DeviceType).Scan(&otherDevice.ID); err != nil {
		t.Fatalf("insert second device: %v", err)
	}
	_, err := operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID: uuid.New(), UserID: fixture.userID, Device: otherDevice,
		ServerID: fixture.serverID, PublicKey: operationKey(20), MaxDevices: 2,
	})
	if !errors.Is(err, repo.ErrPeerOperationConflict) {
		t.Fatalf("cross-device key error = %v; want ErrPeerOperationConflict", err)
	}

	_, err = operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID: uuid.New(), UserID: fixture.userID, Device: otherDevice,
		ServerID: fixture.serverID, PublicKey: operationKey(21), MaxDevices: 1,
	})
	if !errors.Is(err, repo.ErrDeviceLimitReached) {
		t.Fatalf("quota recheck error = %v; want ErrDeviceLimitReached", err)
	}
	_, err = operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID: uuid.New(), UserID: fixture.userID, Device: otherDevice,
		ServerID: fixture.serverID, PublicKey: operationKey(22), MaxDevices: 2,
	})
	if !errors.Is(err, repo.ErrServerCapacity) {
		t.Fatalf("capacity recheck error = %v; want ErrServerCapacity", err)
	}
}

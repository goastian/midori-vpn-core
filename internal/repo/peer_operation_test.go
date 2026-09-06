package repo_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

type peerOperationFixture struct {
	pool     *pgxpool.Pool
	userID   uuid.UUID
	serverID uuid.UUID
	deviceID uuid.UUID
	device   *models.Device
	cipher   *dataencryption.Cipher
}

func newPeerOperationFixture(t *testing.T, maxPeers int) peerOperationFixture {
	t.Helper()
	pool := testPool(t)
	ctx := context.Background()

	var fixture peerOperationFixture
	fixture.pool = pool
	fixture.cipher, _ = dataencryption.New([]byte("0123456789abcdef0123456789abcdef"))
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (authentik_uid, email, display_name)
		VALUES ($1, $2, 'Operation Test User')
		RETURNING id`, uuid.NewString(), uuid.NewString()+"@test.invalid").Scan(&fixture.userID); err != nil {
		t.Fatalf("insert operation user: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO vpn_servers (name, host, max_peers, current_peers, legacy_node_unbound)
		VALUES ($1, 'operation.test.invalid', $2, 0, TRUE)
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

func (f peerOperationFixture) operationRepo() *repo.PeerOperationRepo {
	return repo.NewPeerOperationRepo(f.pool, f.cipher)
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
	operationRepo := fixture.operationRepo()
	key := operationKey(1)
	result := beginFixtureConnect(t, fixture, operationRepo, key)
	var operationLegacy string
	var operationCiphertext []byte
	var operationVersion *int16
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT preshared_key, preshared_key_ciphertext, preshared_key_version
		FROM peer_operations WHERE id = $1`, result.Operation.ID).Scan(
		&operationLegacy, &operationCiphertext, &operationVersion,
	); err != nil {
		t.Fatalf("load protected operation PSK: %v", err)
	}
	if operationLegacy != "" || len(operationCiphertext) == 0 || operationVersion == nil || *operationVersion != dataencryption.CurrentVersion {
		t.Fatalf("operation PSK was not stored exclusively as versioned ciphertext")
	}

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
	ordinaryPeer, err := repo.NewPeerRepo(fixture.pool, fixture.cipher).GetByID(context.Background(), peer.ID)
	if err != nil || ordinaryPeer.PresharedKey != "" {
		t.Fatalf("ordinary peer read exposed PSK: peer=%#v err=%v", ordinaryPeer, err)
	}
	exportPeer, err := repo.NewPeerRepo(fixture.pool, fixture.cipher).GetByIDForPresharedKeyExport(context.Background(), peer.ID, fixture.userID, false)
	if err != nil || exportPeer.PresharedKey != operationKey(200) {
		t.Fatalf("authorized peer export did not decrypt PSK: peer=%#v err=%v", exportPeer, err)
	}
	wrongCipher, _ := dataencryption.New([]byte("abcdef0123456789abcdef0123456789"))
	_, err = repo.NewPeerRepo(fixture.pool, wrongCipher).GetByIDForPresharedKeyExport(context.Background(), peer.ID, uuid.New(), false)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unauthorized export loaded encrypted material: %v", err)
	}
	_, err = repo.NewPeerRepo(fixture.pool, wrongCipher).GetByIDForPresharedKeyExport(context.Background(), peer.ID, fixture.userID, false)
	if err == nil || strings.Contains(err.Error(), operationKey(200)) {
		t.Fatalf("wrong-key export error was unsafe: %v", err)
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

func TestPeerOperationPersistsAutomaticFailoverReason(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := fixture.operationRepo()
	result, err := operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID:      uuid.New(),
		UserID:           fixture.userID,
		Device:           fixture.device,
		ServerID:         fixture.serverID,
		PublicKey:        operationKey(19),
		ConnectionReason: models.ConnectionReasonAutomaticFailover,
		PresharedKey:     operationKey(200),
		MaxDevices:       1,
	})
	if err != nil {
		t.Fatalf("BeginConnect automatic failover: %v", err)
	}
	if result.Operation.ConnectionReason != models.ConnectionReasonAutomaticFailover {
		t.Fatalf("operation reason = %q", result.Operation.ConnectionReason)
	}
	var storedReason models.ConnectionReason
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT connection_reason FROM peer_operations WHERE id = $1`, result.Operation.ID).Scan(&storedReason); err != nil {
		t.Fatalf("load connection reason: %v", err)
	}
	if storedReason != models.ConnectionReasonAutomaticFailover {
		t.Fatalf("stored reason = %q", storedReason)
	}

	_, err = operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID:      uuid.New(),
		UserID:           fixture.userID,
		Device:           fixture.device,
		ServerID:         fixture.serverID,
		PublicKey:        operationKey(20),
		ConnectionReason: models.ConnectionReason("retry"),
		PresharedKey:     operationKey(200),
		MaxDevices:       1,
	})
	if err == nil {
		t.Fatal("BeginConnect accepted an invalid connection reason")
	}
}

func TestPeerOperationRejectsServerWithoutNodeOrLegacyException(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE vpn_servers SET legacy_node_unbound = FALSE WHERE id = $1`, fixture.serverID); err != nil {
		t.Fatalf("remove legacy placement exception: %v", err)
	}

	_, err := fixture.operationRepo().BeginConnect(context.Background(), repo.BeginConnectParams{
		OperationID:  uuid.New(),
		UserID:       fixture.userID,
		Device:       fixture.device,
		ServerID:     fixture.serverID,
		PublicKey:    operationKey(201),
		PresharedKey: operationKey(202),
		MaxDevices:   1,
	})
	if !errors.Is(err, repo.ErrServerPlacement) {
		t.Fatalf("BeginConnect error = %v, want ErrServerPlacement", err)
	}

	var operations, currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT
			(SELECT COUNT(*) FROM peer_operations WHERE user_id = $1),
			(SELECT current_peers FROM vpn_servers WHERE id = $2)`,
		fixture.userID, fixture.serverID).Scan(&operations, &currentPeers); err != nil {
		t.Fatalf("load rejected placement state: %v", err)
	}
	if operations != 0 || currentPeers != 0 {
		t.Fatalf("rejected placement mutated durable state: operations=%d current_peers=%d", operations, currentPeers)
	}
}

func TestPeerOperationReplacementWorksAtQuotaAndCapacityLimit(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := fixture.operationRepo()
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
	var replacementState models.PeerOperationState
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT state FROM peer_operations WHERE id = $1`, second.Operation.ID).Scan(&replacementState); err != nil {
		t.Fatalf("load replacement cleanup state: %v", err)
	}
	if replacementState != models.PeerOperationCleanupPending {
		t.Fatalf("replacement state = %s, want cleanup_pending", replacementState)
	}
	if err := operationRepo.CompleteCleanup(context.Background(), second.Operation.ID); err != nil {
		t.Fatalf("CompleteCleanup: %v", err)
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
	operationRepo := fixture.operationRepo()
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
	operationRepo := fixture.operationRepo()
	first := beginFixtureConnect(t, fixture, operationRepo, operationKey(30))
	completeFixtureConnect(t, operationRepo, first.Operation.ID, "10.90.0.30/32")

	var targetServerID uuid.UUID
	if err := fixture.pool.QueryRow(context.Background(), `
		INSERT INTO vpn_servers (name, host, max_peers, current_peers, legacy_node_unbound)
		VALUES ($1, 'replacement-target.test.invalid', 1, 0, TRUE)
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
	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE vpn_servers SET is_active = FALSE WHERE id = $1`, fixture.serverID); err != nil {
		t.Fatalf("deactivate cleanup source: %v", err)
	}
	reconcilable, err := repo.NewServerRepo(fixture.pool).ListForReconciliation(context.Background())
	if err != nil {
		t.Fatalf("ListForReconciliation: %v", err)
	}
	var sourceIncluded bool
	for _, server := range reconcilable {
		if server.ID == fixture.serverID {
			sourceIncluded = true
			break
		}
	}
	if !sourceIncluded {
		t.Fatal("inactive cross-server cleanup source was not reconcilable")
	}
	if err := operationRepo.CompleteCleanup(context.Background(), replacement.Operation.ID); err != nil {
		t.Fatalf("complete cross-server cleanup: %v", err)
	}
	reconcilable, err = repo.NewServerRepo(fixture.pool).ListForReconciliation(context.Background())
	if err != nil {
		t.Fatalf("ListForReconciliation after cleanup: %v", err)
	}
	for _, server := range reconcilable {
		if server.ID == fixture.serverID {
			t.Fatal("inactive server without durable intent remained reconcilable")
		}
	}
}

func TestPeerOperationDefinitiveFailureReleasesReservation(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := fixture.operationRepo()
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
	operationRepo := fixture.operationRepo()
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
	operationRepo := fixture.operationRepo()

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

func TestPeerOperationFiftyConcurrentSameKeyRequestsConvergeToOnePeer(t *testing.T) {
	fixture := newPeerOperationFixture(t, 50)
	operationRepo := fixture.operationRepo()
	publicKey := operationKey(52)
	const requestCount = 50

	results := make([]*repo.BeginConnectResult, requestCount)
	errorsSeen := make([]error, requestCount)
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(requestCount)
	for index := 0; index < requestCount; index++ {
		index := index
		go func() {
			defer wait.Done()
			<-start
			results[index], errorsSeen[index] = operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
				OperationID:  uuid.New(),
				UserID:       fixture.userID,
				Device:       fixture.device,
				ServerID:     fixture.serverID,
				PublicKey:    publicKey,
				PresharedKey: operationKey(202),
				MaxDevices:   1,
			})
		}()
	}
	close(start)
	wait.Wait()

	winner := -1
	blocked := 0
	for index, err := range errorsSeen {
		switch {
		case err == nil:
			if winner != -1 {
				t.Fatalf("more than one request won: %d and %d", winner, index)
			}
			winner = index
		case errors.Is(err, repo.ErrConnectionInProgress):
			blocked++
		default:
			t.Fatalf("unexpected concurrent result %d: %v", index, err)
		}
	}
	if winner == -1 || blocked != requestCount-1 {
		t.Fatalf("concurrent outcomes: winner=%d blocked=%d", winner, blocked)
	}

	peer, _ := completeFixtureConnect(t, operationRepo, results[winner].Operation.ID, "10.90.0.52/32")
	for index := 0; index < requestCount; index++ {
		retry, err := operationRepo.BeginConnect(context.Background(), repo.BeginConnectParams{
			OperationID:  uuid.New(),
			UserID:       fixture.userID,
			Device:       fixture.device,
			ServerID:     fixture.serverID,
			PublicKey:    publicKey,
			PresharedKey: operationKey(202),
			MaxDevices:   1,
		})
		if err != nil || retry.ExistingPeer == nil || retry.ExistingPeer.ID != peer.ID {
			t.Fatalf("retry %d did not converge to peer %s: result=%#v err=%v", index, peer.ID, retry, err)
		}
	}

	var activePeers, assignedIPs, operations, currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT
			COUNT(*) FILTER (WHERE peer.is_active),
			COUNT(DISTINCT peer.assigned_ip) FILTER (WHERE peer.is_active),
			COUNT(DISTINCT operation.id),
			MAX(server.current_peers)
		FROM peer_operations operation
		JOIN vpn_servers server ON server.id = operation.server_id
		LEFT JOIN peers peer ON peer.provision_operation_id = operation.id
		WHERE operation.user_id = $1 AND operation.public_key = $2`,
		fixture.userID, publicKey).Scan(&activePeers, &assignedIPs, &operations, &currentPeers); err != nil {
		t.Fatalf("load converged concurrent state: %v", err)
	}
	if activePeers != 1 || assignedIPs != 1 || operations != 1 || currentPeers != 1 {
		t.Fatalf("concurrent state diverged: active=%d ips=%d operations=%d slots=%d",
			activePeers, assignedIPs, operations, currentPeers)
	}
}

func TestPeerOperationRechecksQuotaBeforeCapacity(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := fixture.operationRepo()
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

func TestPeerOperationDisconnectIsDurableIdempotentAndRecounts(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := fixture.operationRepo()
	connect := beginFixtureConnect(t, fixture, operationRepo, operationKey(70))
	peer, _ := completeFixtureConnect(t, operationRepo, connect.Operation.ID, "10.90.0.70/32")

	first, err := operationRepo.BeginDisconnect(context.Background(), peer.ID)
	if err != nil {
		t.Fatalf("BeginDisconnect: %v", err)
	}
	second, err := operationRepo.BeginDisconnect(context.Background(), peer.ID)
	if err != nil {
		t.Fatalf("BeginDisconnect retry: %v", err)
	}
	if first.Operation.ID != second.Operation.ID || first.Operation.Action != models.PeerOperationDisconnect ||
		first.Operation.PreviousOperationID == nil || *first.Operation.PreviousOperationID != connect.Operation.ID {
		t.Fatalf("disconnect replay lost exact ownership: first=%#v second=%#v", first.Operation, second.Operation)
	}

	disconnected, err := operationRepo.CompleteDisconnect(context.Background(), first.Operation.ID)
	if err != nil {
		t.Fatalf("CompleteDisconnect: %v", err)
	}
	if disconnected.IsActive {
		t.Fatal("completed disconnect still reports an active peer")
	}
	var state models.PeerOperationState
	var active bool
	var currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT operation.state, peer.is_active, server.current_peers
		FROM peer_operations operation
		JOIN peers peer ON peer.id = operation.previous_peer_id
		JOIN vpn_servers server ON server.id = peer.server_id
		WHERE operation.id = $1`, first.Operation.ID).Scan(&state, &active, &currentPeers); err != nil {
		t.Fatalf("load completed disconnect: %v", err)
	}
	if state != models.PeerOperationCompleted || active || currentPeers != 0 {
		t.Fatalf("disconnect did not converge atomically: state=%s active=%t current=%d", state, active, currentPeers)
	}
	retry, err := operationRepo.BeginDisconnect(context.Background(), peer.ID)
	if err != nil || !retry.AlreadyConverged {
		t.Fatalf("completed disconnect retry = %#v, %v", retry, err)
	}
}

func TestPeerOperationDisconnectRecoversAfterDatabaseFailureFollowingCoreRemoval(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := fixture.operationRepo()
	connect := beginFixtureConnect(t, fixture, operationRepo, operationKey(76))
	peer, _ := completeFixtureConnect(t, operationRepo, connect.Operation.ID, "10.90.0.76/32")
	disconnect, err := operationRepo.BeginDisconnect(context.Background(), peer.ID)
	if err != nil {
		t.Fatalf("BeginDisconnect: %v", err)
	}

	// Core has already confirmed removal. Hold the durable operation row to
	// reproduce PostgreSQL becoming unavailable before the local completion can
	// commit, then verify that a later retry converges the same operation.
	lock, err := fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin failure injection transaction: %v", err)
	}
	if _, err := lock.Exec(context.Background(), `
		SELECT id FROM peer_operations WHERE id = $1 FOR UPDATE`, disconnect.Operation.ID); err != nil {
		_ = lock.Rollback(context.Background())
		t.Fatalf("lock disconnect operation: %v", err)
	}
	failureContext, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, completionErr := operationRepo.CompleteDisconnect(failureContext, disconnect.Operation.ID)
	cancel()
	if completionErr == nil {
		_ = lock.Rollback(context.Background())
		t.Fatal("disconnect completion unexpectedly succeeded while PostgreSQL was blocked")
	}
	if err := lock.Rollback(context.Background()); err != nil {
		t.Fatalf("release failure injection lock: %v", err)
	}

	var state models.PeerOperationState
	var active bool
	var currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT operation.state, peer.is_active, server.current_peers
		FROM peer_operations operation
		JOIN peers peer ON peer.id = operation.previous_peer_id
		JOIN vpn_servers server ON server.id = peer.server_id
		WHERE operation.id = $1`, disconnect.Operation.ID).Scan(&state, &active, &currentPeers); err != nil {
		t.Fatalf("load state after database failure: %v", err)
	}
	if state != models.PeerOperationPending || !active || currentPeers != 1 {
		t.Fatalf("database failure lost durable intent: state=%s active=%t current=%d", state, active, currentPeers)
	}

	disconnected, err := operationRepo.CompleteDisconnect(context.Background(), disconnect.Operation.ID)
	if err != nil {
		t.Fatalf("retry CompleteDisconnect: %v", err)
	}
	if disconnected.IsActive {
		t.Fatal("retry left the peer active")
	}
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT operation.state, peer.is_active, server.current_peers
		FROM peer_operations operation
		JOIN peers peer ON peer.id = operation.previous_peer_id
		JOIN vpn_servers server ON server.id = peer.server_id
		WHERE operation.id = $1`, disconnect.Operation.ID).Scan(&state, &active, &currentPeers); err != nil {
		t.Fatalf("load converged disconnect state: %v", err)
	}
	if state != models.PeerOperationCompleted || active || currentPeers != 0 {
		t.Fatalf("disconnect retry did not converge: state=%s active=%t current=%d", state, active, currentPeers)
	}
}

func TestCompletedConnectCannotCrossConcurrentAccessRevocation(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := fixture.operationRepo()
	pending := beginFixtureConnect(t, fixture, operationRepo, operationKey(71))
	if err := operationRepo.MarkCoreApplied(context.Background(), pending.Operation.ID, "10.90.0.71/32"); err != nil {
		t.Fatalf("MarkCoreApplied: %v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE users SET is_banned = TRUE, banned_at = NOW() WHERE id = $1`, fixture.userID); err != nil {
		t.Fatalf("ban fixture user: %v", err)
	}
	if _, _, err := operationRepo.CompleteConnect(context.Background(), pending.Operation.ID); !errors.Is(err, repo.ErrAccessRevoked) {
		t.Fatalf("CompleteConnect error = %v, want ErrAccessRevoked", err)
	}
	if err := operationRepo.CancelDeniedConnect(context.Background(), pending.Operation.ID); err != nil {
		t.Fatalf("CancelDeniedConnect: %v", err)
	}
	var state models.PeerOperationState
	var currentPeers int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT operation.state, server.current_peers
		FROM peer_operations operation
		JOIN vpn_servers server ON server.id = operation.server_id
		WHERE operation.id = $1`, pending.Operation.ID).Scan(&state, &currentPeers); err != nil {
		t.Fatalf("load canceled operation: %v", err)
	}
	if state != models.PeerOperationFailed || currentPeers != 0 {
		t.Fatalf("denied operation leaked state: state=%s current=%d", state, currentPeers)
	}
}

func TestAdministrativeDeletionRequiresConvergedAccess(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := fixture.operationRepo()
	connect := beginFixtureConnect(t, fixture, operationRepo, operationKey(72))
	peer, _ := completeFixtureConnect(t, operationRepo, connect.Operation.ID, "10.90.0.72/32")
	userRepo := repo.NewUserRepo(fixture.pool)
	if err := userRepo.DeleteIfDrained(context.Background(), fixture.userID); !errors.Is(err, repo.ErrActiveDevicesMustBeDisconnected) {
		t.Fatalf("DeleteIfDrained error = %v", err)
	}
	disconnect, err := operationRepo.BeginDisconnect(context.Background(), peer.ID)
	if err != nil {
		t.Fatalf("BeginDisconnect: %v", err)
	}
	if _, err := operationRepo.CompleteDisconnect(context.Background(), disconnect.Operation.ID); err != nil {
		t.Fatalf("CompleteDisconnect: %v", err)
	}
	if err := userRepo.DeleteIfDrained(context.Background(), fixture.userID); err != nil {
		t.Fatalf("DeleteIfDrained after convergence: %v", err)
	}
}

func TestServerDrainPersistsUntilSessionsConverge(t *testing.T) {
	fixture := newPeerOperationFixture(t, 1)
	operationRepo := fixture.operationRepo()
	connect := beginFixtureConnect(t, fixture, operationRepo, operationKey(73))
	peer, _ := completeFixtureConnect(t, operationRepo, connect.Operation.ID, "10.90.0.73/32")
	serverRepo := repo.NewServerRepo(fixture.pool)
	if err := serverRepo.DrainAndDelete(context.Background(), fixture.serverID); !errors.Is(err, repo.ErrServerNotDrained) {
		t.Fatalf("DrainAndDelete error = %v", err)
	}
	server, err := serverRepo.GetByID(context.Background(), fixture.serverID)
	if err != nil {
		t.Fatalf("GetByID draining server: %v", err)
	}
	if server.IsActive || server.DrainingAt == nil {
		t.Fatalf("server did not enter draining state: %#v", server)
	}
	disconnect, err := operationRepo.BeginDisconnect(context.Background(), peer.ID)
	if err != nil {
		t.Fatalf("BeginDisconnect: %v", err)
	}
	if _, err := operationRepo.CompleteDisconnect(context.Background(), disconnect.Operation.ID); err != nil {
		t.Fatalf("CompleteDisconnect: %v", err)
	}
	if err := serverRepo.DrainAndDelete(context.Background(), fixture.serverID); err != nil {
		t.Fatalf("DrainAndDelete after convergence: %v", err)
	}
}

func TestServerAndTransportsUpdateRollsBackTogether(t *testing.T) {
	pool := testPool(t)
	serverRepo := repo.NewServerRepo(pool)
	server := &models.VPNServer{
		Name: "Atomic server", Host: "atomic.test.invalid", Port: 443, WGPort: 51820,
		MaxPeers: 10, IsActive: true,
	}
	valid := []models.TransportCapability{{
		Protocol: "wireguard", Host: "atomic.test.invalid", Port: 51820,
		Enabled: true, Priority: 100, HealthStatus: "unknown",
	}}
	if err := serverRepo.CreateWithTransports(context.Background(), server, valid); err != nil {
		t.Fatalf("CreateWithTransports: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id = $1`, server.ID) })
	server.Name = "Must roll back"
	invalid := []models.TransportCapability{{
		Protocol: "obsolete", Host: "atomic.test.invalid", Port: 51820,
		Enabled: true, Priority: 100, HealthStatus: "unknown",
	}}
	if err := serverRepo.UpdateWithTransports(context.Background(), server, invalid, true); err == nil {
		t.Fatal("UpdateWithTransports accepted an invalid transport")
	}
	persisted, err := serverRepo.GetByID(context.Background(), server.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if persisted.Name != "Atomic server" || len(persisted.Transports) != 1 || persisted.Transports[0].Protocol != "wireguard" {
		t.Fatalf("partial server update escaped rollback: %#v", persisted)
	}
}

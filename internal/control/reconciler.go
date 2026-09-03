package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

const peerOperationStaleWindow = 2 * time.Minute

type ReconciliationCore interface {
	ListPeers(context.Context, *models.VPNServer) ([]CorePeerStatsResponse, error)
	AddPeer(context.Context, *models.VPNServer, string, string, string) (*CoreAddPeerResponse, error)
	RemovePeer(context.Context, *models.VPNServer, string, string) error
}

type productionReconciliationCore struct{}

func (productionReconciliationCore) ListPeers(ctx context.Context, server *models.VPNServer) ([]CorePeerStatsResponse, error) {
	return CallCoreListPeersContext(ctx, server)
}

func (productionReconciliationCore) AddPeer(ctx context.Context, server *models.VPNServer, publicKey, operationID, presharedKey string) (*CoreAddPeerResponse, error) {
	return CallCoreAddPeerContext(ctx, server, publicKey, operationID, presharedKey)
}

func (productionReconciliationCore) RemovePeer(ctx context.Context, server *models.VPNServer, publicKey, operationID string) error {
	return CallCoreRemovePeerContext(ctx, server, publicKey, operationID)
}

type ReconciliationReport struct {
	ObservedServers   int64
	ObservationErrors int64
	DivergentPeers    int64
	OrphansRemoved    int64
	CleanupPending    int64
	PendingOperations int64
}

type reconciliationMetricState struct {
	observedServers   atomic.Int64
	observationErrors atomic.Int64
	divergentPeers    atomic.Int64
	orphansRemoved    atomic.Int64
	cleanupPending    atomic.Int64
	pendingOperations atomic.Int64
}

var reconciliationMetrics reconciliationMetricState

func ReconciliationMetricsSnapshot() ReconciliationReport {
	return ReconciliationReport{
		ObservedServers:   reconciliationMetrics.observedServers.Load(),
		ObservationErrors: reconciliationMetrics.observationErrors.Load(),
		DivergentPeers:    reconciliationMetrics.divergentPeers.Load(),
		OrphansRemoved:    reconciliationMetrics.orphansRemoved.Load(),
		CleanupPending:    reconciliationMetrics.cleanupPending.Load(),
		PendingOperations: reconciliationMetrics.pendingOperations.Load(),
	}
}

func storeReconciliationMetrics(report ReconciliationReport) {
	reconciliationMetrics.observedServers.Store(report.ObservedServers)
	reconciliationMetrics.observationErrors.Store(report.ObservationErrors)
	reconciliationMetrics.divergentPeers.Store(report.DivergentPeers)
	reconciliationMetrics.orphansRemoved.Store(report.OrphansRemoved)
	reconciliationMetrics.cleanupPending.Store(report.CleanupPending)
	reconciliationMetrics.pendingOperations.Store(report.PendingOperations)
}

type Reconciler struct {
	serverRepo    *repo.ServerRepo
	peerRepo      *repo.PeerRepo
	operationRepo *repo.PeerOperationRepo
	core          ReconciliationCore
}

func NewReconciler(pool *pgxpool.Pool, core ReconciliationCore) *Reconciler {
	if core == nil {
		core = productionReconciliationCore{}
	}
	return &Reconciler{
		serverRepo:    repo.NewServerRepo(pool),
		peerRepo:      repo.NewPeerRepo(pool),
		operationRepo: repo.NewPeerOperationRepo(pool),
		core:          core,
	}
}

type serverObservation struct {
	startedAt time.Time
	peers     []CorePeerStatsResponse
}

func (r *Reconciler) RunOnce(ctx context.Context) ReconciliationReport {
	report := ReconciliationReport{}
	servers, err := r.serverRepo.ListForReconciliation(ctx)
	if err != nil {
		report.ObservationErrors++
		storeReconciliationMetrics(report)
		slog.Error("peer reconciliation could not list servers", "error", err)
		return report
	}
	serverByID := make(map[uuid.UUID]*models.VPNServer, len(servers))
	observations := make(map[uuid.UUID]serverObservation, len(servers))
	for index := range servers {
		server := &servers[index]
		serverByID[server.ID] = server
		startedAt := time.Now()
		peers, err := r.core.ListPeers(ctx, server)
		if err != nil {
			report.ObservationErrors++
			slog.Error("peer reconciliation Core observation failed", "server_id", server.ID, "error", err)
			continue
		}
		report.ObservedServers++
		observations[server.ID] = serverObservation{startedAt: startedAt, peers: peers}
	}

	dirtyServers := make(map[uuid.UUID]bool)
	operations, err := r.operationRepo.ListStaleLive(ctx, peerOperationStaleWindow)
	if err != nil {
		report.ObservationErrors++
		slog.Error("peer reconciliation could not list stale operations", "error", err)
	} else {
		for index := range operations {
			operation := &operations[index]
			switch operation.State {
			case models.PeerOperationPending, models.PeerOperationCoreApplied:
				if err := r.recoverConnect(ctx, operation, serverByID, observations, dirtyServers); err != nil {
					slog.Error("peer reconciliation operation recovery failed", "operation_id", operation.ID, "error", err)
				}
			case models.PeerOperationCleanupPending:
				if err := r.recoverCleanup(ctx, operation, serverByID, observations, dirtyServers); err != nil {
					slog.Error("peer reconciliation pending cleanup failed", "operation_id", operation.ID, "error", err)
				}
			}
		}
	}

	// Core mutations invalidate only the affected snapshots. If the refresh
	// fails, no absence or orphan decision is made for that server.
	for serverID := range dirtyServers {
		server := serverByID[serverID]
		if server == nil {
			delete(observations, serverID)
			continue
		}
		startedAt := time.Now()
		peers, err := r.core.ListPeers(ctx, server)
		if err != nil {
			report.ObservationErrors++
			delete(observations, serverID)
			slog.Error("peer reconciliation post-repair observation failed", "server_id", serverID, "error", err)
			continue
		}
		observations[serverID] = serverObservation{startedAt: startedAt, peers: peers}
	}
	cleanupExact := make(map[uuid.UUID]map[string]bool)
	cleanupKey := make(map[uuid.UUID]map[string]bool)
	if targets, err := r.operationRepo.ListPendingCleanupTargets(ctx); err != nil {
		report.ObservationErrors++
		slog.Error("peer reconciliation could not list cleanup targets", "error", err)
	} else {
		for _, target := range targets {
			if target.OperationID == "" {
				if cleanupKey[target.ServerID] == nil {
					cleanupKey[target.ServerID] = make(map[string]bool)
				}
				cleanupKey[target.ServerID][target.PublicKey] = true
				continue
			}
			if cleanupExact[target.ServerID] == nil {
				cleanupExact[target.ServerID] = make(map[string]bool)
			}
			cleanupExact[target.ServerID][peerOwner(target.PublicKey, target.OperationID)] = true
		}
	}

	for serverID, observation := range observations {
		server := serverByID[serverID]
		converted := make([]repo.PeerObservation, 0, len(observation.peers))
		for _, peer := range observation.peers {
			converted = append(converted, repo.PeerObservation{
				PublicKey: peer.PublicKey, OperationID: peer.OperationID,
				LastHandshake: parseCoreHandshake(peer.LastHandshake),
				BytesSent:     peer.BytesSent, BytesReceived: peer.BytesReceived,
			})
		}
		result, err := r.peerRepo.ReconcileServer(ctx, serverID, observation.startedAt, converted)
		if err != nil {
			report.ObservationErrors++
			slog.Error("peer reconciliation database sync failed", "server_id", serverID, "error", err)
			continue
		}
		report.DivergentPeers += int64(result.DeactivatedPeers)
		ownedExact := make(map[string]bool, len(result.ActivePeers))
		ownedLegacy := make(map[string]bool)
		for _, peer := range result.ActivePeers {
			if peer.ProvisionOperationID == nil {
				ownedLegacy[peer.PublicKey] = true
			} else {
				ownedExact[peerOwner(peer.PublicKey, peer.ProvisionOperationID.String())] = true
			}
		}
		live, err := r.operationRepo.ListLiveByServer(ctx, serverID)
		if err != nil {
			report.ObservationErrors++
			continue
		}
		for _, operation := range live {
			ownedExact[peerOwner(operation.PublicKey, operation.ID.String())] = true
		}
		for _, peer := range observation.peers {
			if ownedLegacy[peer.PublicKey] || ownedExact[peerOwner(peer.PublicKey, peer.OperationID)] ||
				cleanupKey[serverID][peer.PublicKey] || cleanupExact[serverID][peerOwner(peer.PublicKey, peer.OperationID)] {
				continue
			}
			report.DivergentPeers++
			if peer.OperationID == "" {
				report.CleanupPending++
				continue
			}
			if err := r.core.RemovePeer(ctx, server, peer.PublicKey, peer.OperationID); err != nil {
				report.CleanupPending++
				slog.Error("peer reconciliation orphan cleanup failed", "server_id", serverID, "error", err)
				continue
			}
			report.OrphansRemoved++
		}
	}
	if count, err := r.operationRepo.CountLive(ctx); err != nil {
		report.ObservationErrors++
	} else {
		report.PendingOperations = count
	}
	if count, err := r.operationRepo.CountCleanupPending(ctx); err != nil {
		report.ObservationErrors++
	} else {
		report.CleanupPending += count
	}
	storeReconciliationMetrics(report)
	return report
}

func (r *Reconciler) recoverConnect(ctx context.Context, operation *models.PeerOperation, servers map[uuid.UUID]*models.VPNServer, observations map[uuid.UUID]serverObservation, dirty map[uuid.UUID]bool) error {
	server := servers[operation.ServerID]
	observation, valid := observations[operation.ServerID]
	if server == nil || !valid {
		return fmt.Errorf("target Core observation unavailable")
	}
	observed, exists := findObservedPeer(observation.peers, operation.PublicKey, operation.ID.String())
	if !exists {
		if err := r.operationRepo.RecordAttemptStarted(ctx, operation.ID); err != nil {
			if errors.Is(err, repo.ErrOperationState) {
				return nil
			}
			return err
		}
		response, err := r.core.AddPeer(ctx, server, operation.PublicKey, operation.ID.String(), operation.PresharedKey)
		if err != nil {
			_ = r.operationRepo.RecordAttemptFailure(ctx, operation.ID, err)
			return err
		}
		if response.PublicKey != operation.PublicKey || response.OperationID != operation.ID.String() || !validAssignedIP(response.AllowedIP) {
			err := errors.New("core returned mismatched peer operation data")
			_ = r.operationRepo.RecordAttemptFailure(ctx, operation.ID, err)
			return err
		}
		observed = CorePeerStatsResponse{PublicKey: response.PublicKey, OperationID: response.OperationID, AllowedIP: response.AllowedIP}
		dirty[operation.ServerID] = true
	}
	if !validAssignedIP(observed.AllowedIP) {
		err := errors.New("core peer has invalid assigned IP")
		_ = r.operationRepo.RecordAttemptFailure(ctx, operation.ID, err)
		return err
	}
	if err := r.operationRepo.MarkCoreApplied(ctx, operation.ID, observed.AllowedIP); err != nil && !errors.Is(err, repo.ErrOperationState) {
		return err
	}
	_, previousPeer, err := r.operationRepo.CompleteConnect(ctx, operation.ID)
	if err != nil {
		return err
	}
	if previousPeer == nil {
		return nil
	}
	return r.cleanupPrevious(ctx, operation, previousPeer, servers, observations, dirty)
}

func (r *Reconciler) recoverCleanup(ctx context.Context, operation *models.PeerOperation, servers map[uuid.UUID]*models.VPNServer, observations map[uuid.UUID]serverObservation, dirty map[uuid.UUID]bool) error {
	if operation.PreviousPeerID == nil {
		return r.operationRepo.CompleteCleanup(ctx, operation.ID)
	}
	previousPeer, err := r.peerRepo.GetByID(ctx, *operation.PreviousPeerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return r.operationRepo.CompleteCleanup(ctx, operation.ID)
	}
	if err != nil {
		_ = r.operationRepo.RecordAttemptFailure(ctx, operation.ID, err)
		return err
	}
	return r.cleanupPrevious(ctx, operation, previousPeer, servers, observations, dirty)
}

func (r *Reconciler) cleanupPrevious(ctx context.Context, operation *models.PeerOperation, previousPeer *models.Peer, servers map[uuid.UUID]*models.VPNServer, observations map[uuid.UUID]serverObservation, dirty map[uuid.UUID]bool) error {
	server := servers[previousPeer.ServerID]
	observation, valid := observations[previousPeer.ServerID]
	if server == nil || !valid {
		err := errors.New("previous Core observation unavailable")
		return r.markCleanupFailure(ctx, operation, err)
	}
	expectedID := ""
	if operation.PreviousOperationID != nil {
		expectedID = operation.PreviousOperationID.String()
	} else if previousPeer.ProvisionOperationID != nil {
		expectedID = previousPeer.ProvisionOperationID.String()
	}
	observed, exists := findObservedByKey(observation.peers, previousPeer.PublicKey)
	if !exists || (expectedID != "" && observed.OperationID != expectedID) {
		return r.operationRepo.CompleteCleanup(ctx, operation.ID)
	}
	if expectedID == "" {
		expectedID = observed.OperationID
	}
	if expectedID == "" {
		err := errors.New("previous Core operation identity unavailable")
		return r.markCleanupFailure(ctx, operation, err)
	}
	if err := r.operationRepo.RecordAttemptStarted(ctx, operation.ID); err != nil {
		if errors.Is(err, repo.ErrOperationState) {
			return nil
		}
		return err
	}
	if err := r.core.RemovePeer(ctx, server, previousPeer.PublicKey, expectedID); err != nil {
		return r.markCleanupFailure(ctx, operation, err)
	}
	dirty[previousPeer.ServerID] = true
	return r.operationRepo.CompleteCleanup(ctx, operation.ID)
}

func (r *Reconciler) markCleanupFailure(ctx context.Context, operation *models.PeerOperation, cause error) error {
	if err := r.operationRepo.MarkCleanupPending(ctx, operation.ID, cause); err != nil && !errors.Is(err, repo.ErrOperationState) {
		return err
	}
	return cause
}

func peerOwner(publicKey, operationID string) string { return publicKey + "\x00" + operationID }

func findObservedPeer(peers []CorePeerStatsResponse, publicKey, operationID string) (CorePeerStatsResponse, bool) {
	for _, peer := range peers {
		if peer.PublicKey == publicKey && peer.OperationID == operationID {
			return peer, true
		}
	}
	return CorePeerStatsResponse{}, false
}

func findObservedByKey(peers []CorePeerStatsResponse, publicKey string) (CorePeerStatsResponse, bool) {
	for _, peer := range peers {
		if peer.PublicKey == publicKey {
			return peer, true
		}
	}
	return CorePeerStatsResponse{}, false
}

func validAssignedIP(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.IsValid()
}

func parseCoreHandshake(value string) *time.Time {
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.IsZero() {
		return nil
	}
	return &parsed
}

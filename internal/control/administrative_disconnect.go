package control

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

type disconnectOutcome struct {
	OperationID uuid.UUID
	Peer        *models.Peer
	Converged   bool
}

// disconnectPeer records intent before touching Core. Any failure after that
// point is retryable by the reconciler and therefore returns a pending outcome
// rather than pretending the session is gone.
func (h *Handler) disconnectPeer(ctx context.Context, peerID uuid.UUID) (disconnectOutcome, error) {
	result, err := h.peerOperationRepo.BeginDisconnect(ctx, peerID)
	if err != nil {
		return disconnectOutcome{}, err
	}
	if result.AlreadyConverged {
		return disconnectOutcome{Peer: result.Peer, Converged: true}, nil
	}
	outcome := disconnectOutcome{OperationID: result.Operation.ID, Peer: result.Peer}
	server, err := h.serverRepo.GetByID(ctx, result.Peer.ServerID)
	if err != nil {
		h.recordDisconnectFailure(ctx, result.Operation.ID, err)
		return outcome, nil
	}

	expectedOperationID := ""
	if result.Operation.PreviousOperationID != nil {
		expectedOperationID = result.Operation.PreviousOperationID.String()
	} else {
		observed, observeErr := CallCoreGetPeerStatsContext(ctx, server, result.Peer.PublicKey)
		if coreErrorHasStatus(observeErr, http.StatusNotFound) {
			return h.completeDisconnect(ctx, outcome)
		}
		if observeErr != nil {
			h.recordDisconnectFailure(ctx, result.Operation.ID, observeErr)
			return outcome, nil
		}
		parsed, parseErr := uuid.Parse(observed.OperationID)
		if parseErr != nil {
			h.recordDisconnectFailure(ctx, result.Operation.ID, errors.New("core peer operation identity is invalid"))
			return outcome, nil
		}
		expectedOperationID = parsed.String()
		if err := h.peerOperationRepo.SetPreviousOperationID(ctx, result.Operation.ID, parsed); err != nil {
			h.recordDisconnectFailure(ctx, result.Operation.ID, err)
			return outcome, nil
		}
	}
	if err := h.peerOperationRepo.RecordAttemptStarted(ctx, result.Operation.ID); err != nil {
		if errors.Is(err, repo.ErrOperationState) {
			return h.completeDisconnect(ctx, outcome)
		}
		return disconnectOutcome{}, err
	}
	if err := CallCoreRemovePeerContext(ctx, server, result.Peer.PublicKey, expectedOperationID); err != nil {
		h.recordDisconnectFailure(ctx, result.Operation.ID, err)
		return outcome, nil
	}
	return h.completeDisconnect(ctx, outcome)
}

func (h *Handler) completeDisconnect(ctx context.Context, outcome disconnectOutcome) (disconnectOutcome, error) {
	peer, err := h.peerOperationRepo.CompleteDisconnect(ctx, outcome.OperationID)
	if err != nil {
		h.recordDisconnectFailure(ctx, outcome.OperationID, err)
		return outcome, nil
	}
	outcome.Peer = peer
	outcome.Converged = true
	h.serverRepo.InvalidateCache()
	h.detachPeerFromMeshSessions(ctx, peer)
	return outcome, nil
}

func (h *Handler) recordDisconnectFailure(ctx context.Context, operationID uuid.UUID, cause error) {
	if err := h.peerOperationRepo.RecordAttemptFailure(ctx, operationID, cause); err != nil && !errors.Is(err, repo.ErrOperationState) {
		slog.Error("failed to persist disconnect failure", "operation_id", operationID, "error", err)
	}
}

func pendingStatus(status string, operationID uuid.UUID) map[string]string {
	response := map[string]string{"status": status}
	if operationID != uuid.Nil {
		response["operation_id"] = operationID.String()
	}
	return response
}

func respondDisconnect(w http.ResponseWriter, outcome disconnectOutcome, pendingCode string) {
	if outcome.Converged {
		respondStatus(w, "disconnected", http.StatusOK)
		return
	}
	w.Header().Set("Retry-After", "5")
	respondStatusData(w, pendingStatus(pendingCode, outcome.OperationID), http.StatusAccepted)
}

func respondStatus(w http.ResponseWriter, status string, code int) {
	respondStatusData(w, map[string]string{"status": status}, code)
}

func respondStatusData(w http.ResponseWriter, data interface{}, code int) {
	respond.JsonOK(w, data, code)
}

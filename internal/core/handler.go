package core

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/respond"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

type Handler struct {
	cfg *config.Config
	mgr peerManager
}

type peerManager interface {
	AddPeerWithPSK(string, string, int, string) (string, bool, error)
	RemovePeer(string, string) error
	UpdatePeer(string, int) error
	PeerStats(string) (*wg.PeerInfo, error)
	ListPeers() ([]wg.PeerInfo, error)
	ServerStats() (*wg.ServerStatsResponse, error)
}

func NewHandler(cfg *config.Config, mgr *wg.Manager) *Handler {
	return newHandler(cfg, mgr)
}

func newHandler(cfg *config.Config, mgr peerManager) *Handler {
	return &Handler{cfg: cfg, mgr: mgr}
}

// --- Health ---

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	respond.JsonOK(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// --- Peers ---

type AddPeerRequest struct {
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key,omitempty"`
	Keepalive    int    `json:"keepalive"`
	OperationID  string `json:"operation_id"`
}

type AddPeerResponse struct {
	PublicKey   string `json:"public_key"`
	OperationID string `json:"operation_id"`
	AllowedIP   string `json:"allowed_ip"`
	Endpoint    string `json:"endpoint"`
}

func (h *Handler) AddPeer(w http.ResponseWriter, r *http.Request) {
	var req AddPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.PublicKey == "" {
		respond.JsonError(w, "public_key is required", http.StatusBadRequest)
		return
	}

	if req.Keepalive == 0 {
		req.Keepalive = 25
	}

	var ip string
	var created bool
	var endpoint string
	mutate := func(endpointHost string, endpointPort int) error {
		endpoint = ""
		if endpointHost != "" {
			endpoint = net.JoinHostPort(endpointHost, strconv.Itoa(endpointPort))
		}
		var err error
		ip, created, err = h.mgr.AddPeerWithPSK(req.PublicKey, req.OperationID, req.Keepalive, req.PresharedKey)
		return err
	}
	var err error
	if h.cfg.RuntimePolicy != nil {
		called := false
		err = h.cfg.RuntimePolicy.WithWireGuardEndpoint(func(host string, port int) error {
			called = true
			return mutate(host, port)
		})
		if !called {
			respond.JsonErrorCode(w, "WireGuard is unavailable in signed desired state", "core_desired_state_unavailable", http.StatusServiceUnavailable)
			return
		}
	} else {
		err = mutate(h.cfg.Endpoint, h.cfg.WGPort)
	}
	if err != nil {
		respondPeerMutationError(w, "failed to add peer", err)
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	respond.JsonOK(w, AddPeerResponse{
		PublicKey:   req.PublicKey,
		OperationID: req.OperationID,
		AllowedIP:   ip,
		Endpoint:    endpoint,
	}, status)
}

func (h *Handler) RemovePeer(w http.ResponseWriter, r *http.Request) {
	pubkey, err := url.PathUnescape(chi.URLParam(r, "pubkey"))
	if err != nil {
		respond.JsonError(w, "invalid pubkey in URL", http.StatusBadRequest)
		return
	}

	expectedOperationID := r.URL.Query().Get("expected_operation_id")
	if expectedOperationID == "" {
		respond.JsonError(w, "expected_operation_id is required", http.StatusBadRequest)
		return
	}

	if err := h.mgr.RemovePeer(pubkey, expectedOperationID); err != nil {
		respondPeerMutationError(w, "failed to remove peer", err)
		return
	}

	respond.JsonOK(w, map[string]string{"removed": pubkey}, http.StatusOK)
}

type UpdatePeerRequest struct {
	Keepalive *int `json:"keepalive,omitempty"`
}

func (h *Handler) UpdatePeer(w http.ResponseWriter, r *http.Request) {
	pubkey, err := url.PathUnescape(chi.URLParam(r, "pubkey"))
	if err != nil {
		respond.JsonError(w, "invalid pubkey in URL", http.StatusBadRequest)
		return
	}

	var req UpdatePeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	keepalive := 25
	if req.Keepalive != nil {
		keepalive = *req.Keepalive
	}

	if err := h.mgr.UpdatePeer(pubkey, keepalive); err != nil {
		respondPeerMutationError(w, "failed to update peer", err)
		return
	}

	respond.JsonOK(w, map[string]string{"updated": pubkey}, http.StatusOK)
}

func (h *Handler) PeerStats(w http.ResponseWriter, r *http.Request) {
	pubkey, err := url.PathUnescape(chi.URLParam(r, "pubkey"))
	if err != nil {
		respond.JsonError(w, "invalid pubkey in URL", http.StatusBadRequest)
		return
	}

	stats, err := h.mgr.PeerStats(pubkey)
	if err != nil {
		if errors.Is(err, wg.ErrInvalidPublicKey) {
			respond.JsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, wg.ErrPeerStateUnavailable) || errors.Is(err, wg.ErrPeerOperationUntracked) {
			respond.JsonErrorCode(w, "WireGuard peer state is unavailable", "core_peer_state_unavailable", http.StatusServiceUnavailable)
			return
		}
		respond.SafeError(w, "peer not found", err, http.StatusNotFound)
		return
	}

	respond.JsonOK(w, stats, http.StatusOK)
}

func (h *Handler) ListPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := h.mgr.ListPeers()
	if err != nil {
		slog.Error("failed to list peers", "error", err)
		respond.JsonErrorCode(w, "WireGuard peer state is unavailable", "core_peer_state_unavailable", http.StatusServiceUnavailable)
		return
	}

	respond.JsonOK(w, peers, http.StatusOK)
}

func respondPeerMutationError(w http.ResponseWriter, publicMessage string, err error) {
	switch {
	case errors.Is(err, wg.ErrInvalidPublicKey),
		errors.Is(err, wg.ErrInvalidPresharedKey),
		errors.Is(err, wg.ErrInvalidOperationID),
		errors.Is(err, wg.ErrInvalidKeepalive):
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, wg.ErrPeerOperationConflict):
		respond.JsonErrorCode(w, "peer is owned by another operation", "peer_operation_conflict", http.StatusConflict)
	case errors.Is(err, wg.ErrPeerCapacityReached):
		respond.JsonErrorCode(w, "Core node peer capacity is reached", "core_peer_capacity_reached", http.StatusConflict)
	case errors.Is(err, wg.ErrPeerStateUnavailable), errors.Is(err, wg.ErrPeerOperationUntracked):
		respond.JsonErrorCode(w, "WireGuard peer state is unavailable", "core_peer_state_unavailable", http.StatusServiceUnavailable)
	default:
		respond.SafeError(w, publicMessage, err, http.StatusInternalServerError)
	}
}

// --- Stats ---

func (h *Handler) ServerStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.mgr.ServerStats()
	if err != nil {
		respond.SafeError(w, "failed to get server stats", err, http.StatusInternalServerError)
		return
	}

	respond.JsonOK(w, stats, http.StatusOK)
}

package core

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/goastian/midori-vpn-core/internal/api"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/crypto"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

type Handler struct {
	cfg *config.Config
	mgr *wg.Manager
}

func NewHandler(cfg *config.Config, mgr *wg.Manager) *Handler {
	return &Handler{cfg: cfg, mgr: mgr}
}

// --- Health ---

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	api.JsonOK(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// --- Peers ---

type AddPeerRequest struct {
	PublicKey  string `json:"public_key"`
	Keepalive int    `json:"keepalive"`
}

type AddPeerResponse struct {
	PublicKey  string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
	Endpoint  string `json:"endpoint"`
}

func (h *Handler) AddPeer(w http.ResponseWriter, r *http.Request) {
	var req AddPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.PublicKey == "" {
		api.JsonError(w, "public_key is required", http.StatusBadRequest)
		return
	}

	if req.Keepalive == 0 {
		req.Keepalive = 25
	}

	ip, err := h.mgr.AddPeer(req.PublicKey, req.Keepalive)
	if err != nil {
		api.JsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	endpoint := h.cfg.Endpoint
	if endpoint != "" {
		endpoint = endpoint + ":" + strconv.Itoa(h.cfg.WGPort)
	}

	api.JsonOK(w, AddPeerResponse{
		PublicKey:  req.PublicKey,
		AllowedIP: ip,
		Endpoint:  endpoint,
	}, http.StatusCreated)
}

func (h *Handler) RemovePeer(w http.ResponseWriter, r *http.Request) {
	pubkey, err := url.PathUnescape(chi.URLParam(r, "pubkey"))
	if err != nil {
		api.JsonError(w, "invalid pubkey in URL", http.StatusBadRequest)
		return
	}

	if err := h.mgr.RemovePeer(pubkey); err != nil {
		api.JsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	api.JsonOK(w, map[string]string{"removed": pubkey}, http.StatusOK)
}

type UpdatePeerRequest struct {
	Keepalive *int `json:"keepalive,omitempty"`
}

func (h *Handler) UpdatePeer(w http.ResponseWriter, r *http.Request) {
	pubkey, err := url.PathUnescape(chi.URLParam(r, "pubkey"))
	if err != nil {
		api.JsonError(w, "invalid pubkey in URL", http.StatusBadRequest)
		return
	}

	var req UpdatePeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	keepalive := 25
	if req.Keepalive != nil {
		keepalive = *req.Keepalive
	}

	if err := h.mgr.UpdatePeer(pubkey, keepalive); err != nil {
		api.JsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	api.JsonOK(w, map[string]string{"updated": pubkey}, http.StatusOK)
}

func (h *Handler) PeerStats(w http.ResponseWriter, r *http.Request) {
	pubkey, err := url.PathUnescape(chi.URLParam(r, "pubkey"))
	if err != nil {
		api.JsonError(w, "invalid pubkey in URL", http.StatusBadRequest)
		return
	}

	stats, err := h.mgr.PeerStats(pubkey)
	if err != nil {
		api.JsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	api.JsonOK(w, stats, http.StatusOK)
}

func (h *Handler) ListPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := h.mgr.ListPeers()
	if err != nil {
		api.JsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	api.JsonOK(w, peers, http.StatusOK)
}

// --- Keypair ---

func (h *Handler) GenerateKeypair(w http.ResponseWriter, r *http.Request) {
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		api.JsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	api.JsonOK(w, kp, http.StatusCreated)
}

// --- Stats ---

func (h *Handler) ServerStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.mgr.ServerStats()
	if err != nil {
		api.JsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	api.JsonOK(w, stats, http.StatusOK)
}


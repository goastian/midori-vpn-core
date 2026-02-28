package api

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/goastian/astian-vpn-core/internal/config"
	"github.com/goastian/astian-vpn-core/internal/crypto"
	"github.com/goastian/astian-vpn-core/internal/wg"
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
	jsonOK(w, map[string]string{"status": "ok"}, http.StatusOK)
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
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.PublicKey == "" {
		jsonError(w, "public_key is required", http.StatusBadRequest)
		return
	}

	if req.Keepalive == 0 {
		req.Keepalive = 25
	}

	ip, err := h.mgr.AddPeer(req.PublicKey, req.Keepalive)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	endpoint := h.cfg.Endpoint
	if endpoint != "" {
		endpoint = endpoint + ":" + itoa(h.cfg.WGPort)
	}

	jsonOK(w, AddPeerResponse{
		PublicKey:  req.PublicKey,
		AllowedIP: ip,
		Endpoint:  endpoint,
	}, http.StatusCreated)
}

func (h *Handler) RemovePeer(w http.ResponseWriter, r *http.Request) {
	pubkey, err := url.PathUnescape(chi.URLParam(r, "pubkey"))
	if err != nil {
		jsonError(w, "invalid pubkey in URL", http.StatusBadRequest)
		return
	}

	if err := h.mgr.RemovePeer(pubkey); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{"removed": pubkey}, http.StatusOK)
}

type UpdatePeerRequest struct {
	Keepalive *int `json:"keepalive,omitempty"`
}

func (h *Handler) UpdatePeer(w http.ResponseWriter, r *http.Request) {
	pubkey, err := url.PathUnescape(chi.URLParam(r, "pubkey"))
	if err != nil {
		jsonError(w, "invalid pubkey in URL", http.StatusBadRequest)
		return
	}

	var req UpdatePeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	keepalive := 25
	if req.Keepalive != nil {
		keepalive = *req.Keepalive
	}

	if err := h.mgr.UpdatePeer(pubkey, keepalive); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{"updated": pubkey}, http.StatusOK)
}

func (h *Handler) PeerStats(w http.ResponseWriter, r *http.Request) {
	pubkey, err := url.PathUnescape(chi.URLParam(r, "pubkey"))
	if err != nil {
		jsonError(w, "invalid pubkey in URL", http.StatusBadRequest)
		return
	}

	stats, err := h.mgr.PeerStats(pubkey)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	jsonOK(w, stats, http.StatusOK)
}

func (h *Handler) ListPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := h.mgr.ListPeers()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, peers, http.StatusOK)
}

// --- Keypair ---

func (h *Handler) GenerateKeypair(w http.ResponseWriter, r *http.Request) {
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, kp, http.StatusCreated)
}

// --- Stats ---

func (h *Handler) ServerStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.mgr.ServerStats()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, stats, http.StatusOK)
}

// helper
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 6)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

type ControlHandler struct {
	serverRepo *repo.ServerRepo
	peerRepo   *repo.PeerRepo
	auditRepo  *repo.AuditRepo
}

func NewControlHandler(pool *pgxpool.Pool) *ControlHandler {
	return &ControlHandler{
		serverRepo: repo.NewServerRepo(pool),
		peerRepo:   repo.NewPeerRepo(pool),
		auditRepo:  repo.NewAuditRepo(pool),
	}
}

// --- User profile ---

func (h *ControlHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		jsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	jsonOK(w, user, http.StatusOK)
}

// --- Servers ---

func (h *ControlHandler) ListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListActive(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, servers, http.StatusOK)
}

type CreateServerRequest struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	WGPort      int    `json:"wg_port"`
	PublicKey   string `json:"public_key"`
	CoreToken   string `json:"core_token"`
	Location    string `json:"location"`
	CountryCode string `json:"country_code"`
	MaxPeers    int    `json:"max_peers"`
}

func (h *ControlHandler) CreateServer(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if !isAdmin(user) {
		jsonError(w, "admin access required", http.StatusForbidden)
		return
	}

	var req CreateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Host == "" || req.PublicKey == "" || req.CoreToken == "" {
		jsonError(w, "name, host, public_key and core_token are required", http.StatusBadRequest)
		return
	}

	if req.Port == 0 {
		req.Port = 8080
	}
	if req.WGPort == 0 {
		req.WGPort = 51820
	}
	if req.MaxPeers == 0 {
		req.MaxPeers = 250
	}

	server := &models.VPNServer{
		Name:        req.Name,
		Host:        req.Host,
		Port:        req.Port,
		WGPort:      req.WGPort,
		PublicKey:    req.PublicKey,
		CoreToken:   req.CoreToken,
		Location:    req.Location,
		CountryCode: req.CountryCode,
		MaxPeers:    req.MaxPeers,
	}

	if err := h.serverRepo.Create(r.Context(), server); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditRepo.Log(r.Context(), &user.ID, "server.create",
		map[string]interface{}{"server_id": server.ID, "name": server.Name}, r.RemoteAddr)

	jsonOK(w, server, http.StatusCreated)
}

func (h *ControlHandler) DeleteServer(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if !isAdmin(user) {
		jsonError(w, "admin access required", http.StatusForbidden)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid server id", http.StatusBadRequest)
		return
	}

	if err := h.serverRepo.Delete(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditRepo.Log(r.Context(), &user.ID, "server.delete",
		map[string]interface{}{"server_id": id}, r.RemoteAddr)

	jsonOK(w, map[string]string{"deleted": id.String()}, http.StatusOK)
}

// --- Peers ---

type ConnectPeerRequest struct {
	ServerID  string `json:"server_id"`
	PublicKey string `json:"public_key"`
}

func (h *ControlHandler) ListMyPeers(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	peers, err := h.peerRepo.ListByUser(r.Context(), user.ID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, peers, http.StatusOK)
}

func (h *ControlHandler) ConnectPeer(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	var req ConnectPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.ServerID == "" || req.PublicKey == "" {
		jsonError(w, "server_id and public_key are required", http.StatusBadRequest)
		return
	}

	serverID, err := uuid.Parse(req.ServerID)
	if err != nil {
		jsonError(w, "invalid server_id", http.StatusBadRequest)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), serverID)
	if err != nil {
		jsonError(w, "server not found", http.StatusNotFound)
		return
	}

	coreResp, err := callCoreAddPeer(server, req.PublicKey)
	if err != nil {
		jsonError(w, fmt.Sprintf("core error: %v", err), http.StatusBadGateway)
		return
	}

	peer := &models.Peer{
		UserID:     user.ID,
		ServerID:   serverID,
		PublicKey:  req.PublicKey,
		AssignedIP: coreResp.AllowedIP,
	}

	if err := h.peerRepo.Create(r.Context(), peer); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = h.serverRepo.UpdatePeerCount(r.Context(), serverID, 1)

	h.auditRepo.Log(r.Context(), &user.ID, "peer.connect",
		map[string]interface{}{
			"peer_id":   peer.ID,
			"server_id": serverID,
			"ip":        peer.AssignedIP,
		}, r.RemoteAddr)

	jsonOK(w, map[string]interface{}{
		"peer":       peer,
		"endpoint":   fmt.Sprintf("%s:%d", server.Host, server.WGPort),
		"server_key": server.PublicKey,
		"allowed_ip": coreResp.AllowedIP,
	}, http.StatusCreated)
}

func (h *ControlHandler) DisconnectPeer(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	peerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	peer, err := h.peerRepo.GetByID(r.Context(), peerID)
	if err != nil {
		jsonError(w, "peer not found", http.StatusNotFound)
		return
	}

	if peer.UserID != user.ID && !isAdmin(user) {
		jsonError(w, "not your peer", http.StatusForbidden)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err == nil {
		_ = callCoreRemovePeer(server, peer.PublicKey)
		_ = h.serverRepo.UpdatePeerCount(r.Context(), peer.ServerID, -1)
	}

	if err := h.peerRepo.Delete(r.Context(), peerID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditRepo.Log(r.Context(), &user.ID, "peer.disconnect",
		map[string]interface{}{"peer_id": peerID}, r.RemoteAddr)

	jsonOK(w, map[string]string{"status": "disconnected"}, http.StatusOK)
}

// --- Audit ---

func (h *ControlHandler) MyAuditLogs(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	logs, err := h.auditRepo.ListByUser(r.Context(), user.ID, 50, 0)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, logs, http.StatusOK)
}

// --- Helpers ---

func isAdmin(user *models.User) bool {
	if user == nil {
		return false
	}
	for _, g := range user.Groups {
		if g == "vpn-admins" || g == "admins" {
			return true
		}
	}
	return false
}

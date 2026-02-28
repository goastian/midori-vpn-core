package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

type ControlHandler struct {
	userRepo   *repo.UserRepo
	serverRepo *repo.ServerRepo
	peerRepo   *repo.PeerRepo
	auditRepo  *repo.AuditRepo
	subRepo    *repo.SubscriptionRepo
}

func NewControlHandler(pool *pgxpool.Pool) *ControlHandler {
	return &ControlHandler{
		userRepo:   repo.NewUserRepo(pool),
		serverRepo: repo.NewServerRepo(pool),
		peerRepo:   repo.NewPeerRepo(pool),
		auditRepo:  repo.NewAuditRepo(pool),
		subRepo:    repo.NewSubscriptionRepo(pool),
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// User profile
// ═══════════════════════════════════════════════════════════════════════════

func (h *ControlHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		jsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	sub, _ := h.subRepo.EnsureFree(r.Context(), user.ID)
	jsonOK(w, map[string]interface{}{
		"user":         user,
	}, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Servers (user-facing: list active only)
// ═══════════════════════════════════════════════════════════════════════════

func (h *ControlHandler) ListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListActive(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, servers, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Connections — full VPN connection flow
// ═══════════════════════════════════════════════════════════════════════════

type ConnectRequest struct {
	ServerID   string `json:"server_id"`
	PublicKey  string `json:"public_key"`
	DeviceName string `json:"device_name"`
}

func (h *ControlHandler) Connect(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	// 1. Validate banned
	if user.IsBanned {
		jsonError(w, "account is banned", http.StatusForbidden)
		return
	}

	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		jsonError(w, "public_key is required", http.StatusBadRequest)
		return
	}

	// 2. Validate device limit
	activeCount, err := h.peerRepo.CountByUser(r.Context(), user.ID)
	if err != nil {
		jsonError(w, "device count failed", http.StatusInternalServerError)
		return
	}
	if activeCount >= sub.MaxDevices {
		jsonError(w, fmt.Sprintf("device limit reached (%d/%d)", activeCount, sub.MaxDevices), http.StatusConflict)
		return
	}

	// 3. Select server (explicit or least loaded)
	var server *models.VPNServer
	if req.ServerID != "" {
		serverID, err := uuid.Parse(req.ServerID)
		if err != nil {
			jsonError(w, "invalid server_id", http.StatusBadRequest)
			return
		}
		server, err = h.serverRepo.GetByID(r.Context(), serverID)
		if err != nil {
			jsonError(w, "server not found", http.StatusNotFound)
			return
		}
		if !server.IsActive || server.CurrentPeers >= server.MaxPeers {
			jsonError(w, "server is full or inactive", http.StatusConflict)
			return
		}
	} else {
		server, err = h.serverRepo.LeastLoaded(r.Context())
		if err != nil {
			jsonError(w, "no available servers", http.StatusServiceUnavailable)
			return
		}
	}

	// 4+5. Call vpn-core to add peer (core assigns IP from pool)
	coreResp, err := callCoreAddPeer(server, req.PublicKey)
	if err != nil {
		jsonError(w, fmt.Sprintf("core error: %v", err), http.StatusBadGateway)
		return
	}

	// 7. Save peer in DB
	peer := &models.Peer{
		UserID:     user.ID,
		ServerID:   server.ID,
		PublicKey:  req.PublicKey,
		AssignedIP: coreResp.AllowedIP,
		DeviceName: req.DeviceName,
	}
	if err := h.peerRepo.Create(r.Context(), peer); err != nil {
		_ = callCoreRemovePeer(server, req.PublicKey)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = h.serverRepo.UpdatePeerCount(r.Context(), server.ID, 1)

	h.auditRepo.Log(r.Context(), &user.ID, "peer.connect",
		map[string]interface{}{
			"peer_id":     peer.ID,
			"server_id":   server.ID,
			"ip":          peer.AssignedIP,
			"device_name": req.DeviceName,
		}, r.RemoteAddr)

	// 8. Return full WireGuard config
	config := models.ConnectionConfig{
		PeerID:          peer.ID,
		PeerIP:          coreResp.AllowedIP,
		ServerPublicKey: server.PublicKey,
		ServerEndpoint:  fmt.Sprintf("%s:%d", server.Host, server.WGPort),
		DNS:             "1.1.1.1, 8.8.8.8",
		AllowedIPs:      "0.0.0.0/0, ::/0",
	}

	jsonOK(w, config, http.StatusCreated)
}

func (h *ControlHandler) Disconnect(w http.ResponseWriter, r *http.Request) {
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

	_ = h.peerRepo.Deactivate(r.Context(), peerID)

	h.auditRepo.Log(r.Context(), &user.ID, "peer.disconnect",
		map[string]interface{}{"peer_id": peerID, "server_id": peer.ServerID}, r.RemoteAddr)

	jsonOK(w, map[string]string{"status": "disconnected"}, http.StatusOK)
}

func (h *ControlHandler) ListMyConnections(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	peers, err := h.peerRepo.ListByUser(r.Context(), user.ID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, peers, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// User audit
// ═══════════════════════════════════════════════════════════════════════════

func (h *ControlHandler) MyAuditLogs(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	logs, err := h.auditRepo.ListByUser(r.Context(), user.ID, 50, 0)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, logs, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Admin API
// ═══════════════════════════════════════════════════════════════════════════

func (h *ControlHandler) AdminDashboardStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	totalUsers, _ := h.userRepo.Count(ctx)
	totalServers, activeServers, _ := h.serverRepo.Count(ctx)
	totalPeers, activePeers, _ := h.peerRepo.CountAll(ctx)
	totalSubs, _ := h.subRepo.CountActive(ctx)
	bytesSent, bytesRecv, _ := h.peerRepo.TotalTraffic(ctx)

	stats := models.AdminStats{
		TotalUsers:         totalUsers,
		TotalServers:       totalServers,
		ActiveServers:      activeServers,
		TotalPeers:         totalPeers,
		ActivePeers:        activePeers,
		TotalSubscriptions: totalSubs,
		TotalBytesSent:     bytesSent,
		TotalBytesRecv:     bytesRecv,
	}
	jsonOK(w, stats, http.StatusOK)
}

func (h *ControlHandler) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationParams(r)
	users, err := h.userRepo.List(r.Context(), limit, offset)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, users, http.StatusOK)
}

func (h *ControlHandler) AdminGetUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), id)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	peers, _ := h.peerRepo.ListByUser(r.Context(), id)
	sub, _ := h.subRepo.GetActiveByUser(r.Context(), id)

	jsonOK(w, map[string]interface{}{
		"user":         user,
		"peers":        peers,
		"subscription": sub,
	}, http.StatusOK)
}

type AdminCreateUserRequest struct {
	AuthentikUID string   `json:"authentik_uid"`
	Email        string   `json:"email"`
	DisplayName  string   `json:"display_name"`
	Groups       []string `json:"groups"`
}

func (h *ControlHandler) AdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req AdminCreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.AuthentikUID == "" || req.Email == "" {
		jsonError(w, "authentik_uid and email are required", http.StatusBadRequest)
		return
	}

	user := &models.User{
		AuthentikUID: req.AuthentikUID,
		Email:        req.Email,
		DisplayName:  req.DisplayName,
		Groups:       req.Groups,
	}
	if user.Groups == nil {
		user.Groups = []string{}
	}

	if err := h.userRepo.Create(r.Context(), user); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ = h.subRepo.EnsureFree(r.Context(), user.ID)

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.create",
		map[string]interface{}{"target_user_id": user.ID}, r.RemoteAddr)

	jsonOK(w, user, http.StatusCreated)
}

type AdminUpdateUserRequest struct {
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Groups      []string `json:"groups"`
}

func (h *ControlHandler) AdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), id)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	var req AdminUpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Email != "" {
		user.Email = req.Email
	}
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.Groups != nil {
		user.Groups = req.Groups
	}

	if err := h.userRepo.Update(r.Context(), user); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.update",
		map[string]interface{}{"target_user_id": id}, r.RemoteAddr)

	jsonOK(w, user, http.StatusOK)
}

func (h *ControlHandler) AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	if err := h.userRepo.Delete(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.delete",
		map[string]interface{}{"target_user_id": id}, r.RemoteAddr)

	jsonOK(w, map[string]string{"deleted": id.String()}, http.StatusOK)
}

type BanRequest struct {
	Reason string `json:"reason"`
}

func (h *ControlHandler) AdminBanUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	var req BanRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if err := h.userRepo.Ban(r.Context(), id, req.Reason); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Disconnect all active peers for banned user
	peers, _ := h.peerRepo.ListByUser(r.Context(), id)
	for _, p := range peers {
		if !p.IsActive {
			continue
		}
		server, err := h.serverRepo.GetByID(r.Context(), p.ServerID)
		if err == nil {
			_ = callCoreRemovePeer(server, p.PublicKey)
			_ = h.serverRepo.UpdatePeerCount(r.Context(), p.ServerID, -1)
		}
		_ = h.peerRepo.Deactivate(r.Context(), p.ID)
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.ban",
		map[string]interface{}{"target_user_id": id, "reason": req.Reason}, r.RemoteAddr)

	jsonOK(w, map[string]string{"status": "banned"}, http.StatusOK)
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

func (h *ControlHandler) AdminListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListAll(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, servers, http.StatusOK)
}

func (h *ControlHandler) AdminCreateServer(w http.ResponseWriter, r *http.Request) {
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

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.server.create",
		map[string]interface{}{"server_id": server.ID, "name": server.Name}, r.RemoteAddr)

	jsonOK(w, server, http.StatusCreated)
}

type UpdateServerRequest struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	WGPort      int    `json:"wg_port"`
	PublicKey   string `json:"public_key"`
	CoreToken   string `json:"core_token"`
	Location    string `json:"location"`
	CountryCode string `json:"country_code"`
	MaxPeers    int    `json:"max_peers"`
	IsActive    *bool  `json:"is_active"`
}

func (h *ControlHandler) AdminUpdateServer(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid server id", http.StatusBadRequest)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), id)
	if err != nil {
		jsonError(w, "server not found", http.StatusNotFound)
		return
	}

	var req UpdateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Name != "" {
		server.Name = req.Name
	}
	if req.Host != "" {
		server.Host = req.Host
	}
	if req.Port != 0 {
		server.Port = req.Port
	}
	if req.WGPort != 0 {
		server.WGPort = req.WGPort
	}
	if req.PublicKey != "" {
		server.PublicKey = req.PublicKey
	}
	if req.CoreToken != "" {
		server.CoreToken = req.CoreToken
	}
	if req.Location != "" {
		server.Location = req.Location
	}
	if req.CountryCode != "" {
		server.CountryCode = req.CountryCode
	}
	if req.MaxPeers != 0 {
		server.MaxPeers = req.MaxPeers
	}
	if req.IsActive != nil {
		server.IsActive = *req.IsActive
	}

	if err := h.serverRepo.Update(r.Context(), server); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.server.update",
		map[string]interface{}{"server_id": id}, r.RemoteAddr)

	jsonOK(w, server, http.StatusOK)
}

func (h *ControlHandler) AdminDeleteServer(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid server id", http.StatusBadRequest)
		return
	}

	if err := h.serverRepo.Delete(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.server.delete",
		map[string]interface{}{"server_id": id}, r.RemoteAddr)

	jsonOK(w, map[string]string{"deleted": id.String()}, http.StatusOK)
}

func (h *ControlHandler) AdminListPeers(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationParams(r)
	peers, err := h.peerRepo.ListAll(r.Context(), limit, offset)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, peers, http.StatusOK)
}

func (h *ControlHandler) AdminForceDisconnectPeer(w http.ResponseWriter, r *http.Request) {
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

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err == nil {
		_ = callCoreRemovePeer(server, peer.PublicKey)
		_ = h.serverRepo.UpdatePeerCount(r.Context(), peer.ServerID, -1)
	}

	_ = h.peerRepo.Deactivate(r.Context(), peerID)

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.peer.disconnect",
		map[string]interface{}{"peer_id": peerID, "user_id": peer.UserID}, r.RemoteAddr)

	jsonOK(w, map[string]string{"status": "disconnected"}, http.StatusOK)
}

func (h *ControlHandler) AdminListAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationParams(r)
	action := r.URL.Query().Get("action")
	logs, err := h.auditRepo.ListAll(r.Context(), limit, offset, action)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, logs, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

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

func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r)
		if !isAdmin(user) {
			jsonError(w, "admin access required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func paginationParams(r *http.Request) (int, int) {
	limit := 50
	offset := 0
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 200 {
		limit = l
	}
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o >= 0 {
		offset = o
	}
	return limit, offset
}

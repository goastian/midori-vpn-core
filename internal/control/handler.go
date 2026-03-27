package control

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	vpnCrypto "github.com/goastian/midori-vpn-core/internal/crypto"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

type Handler struct {
	userRepo          *repo.UserRepo
	serverRepo        *repo.ServerRepo
	peerRepo          *repo.PeerRepo
	auditRepo         *repo.AuditRepo
	maxDevicesPerUser int
}

func NewHandler(pool *pgxpool.Pool, cfg *config.Config) *Handler {
	return &Handler{
		userRepo:          repo.NewUserRepo(pool),
		serverRepo:        repo.NewServerRepo(pool),
		peerRepo:          repo.NewPeerRepo(pool),
		auditRepo:         repo.NewAuditRepo(pool),
		maxDevicesPerUser: cfg.MaxDevicesPerUser,
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// User profile
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	respond.JsonOK(w, user, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Keypair generation (browser-side)
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) GenerateKeypair(w http.ResponseWriter, r *http.Request) {
	kp, err := vpnCrypto.GenerateKeypair()
	if err != nil {
		log.Printf("keypair generation error: %v", err)
		respond.JsonError(w, "failed to generate keypair", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, kp, http.StatusCreated)
}

// ═══════════════════════════════════════════════════════════════════════════
// Servers (user-facing: list active only)
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) ListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListActive(r.Context())
	if err != nil {
		log.Printf("list servers error: %v", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, servers, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Server latency ping
// ═══════════════════════════════════════════════════════════════════════════

type ServerPingResult struct {
	ServerID    uuid.UUID `json:"server_id"`
	Name        string    `json:"name"`
	Host        string    `json:"host"`
	Location    string    `json:"location"`
	CountryCode string    `json:"country_code"`
	LatencyMs   int64     `json:"latency_ms"`
	Available   bool      `json:"available"`
}

func (h *Handler) PingServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListActive(r.Context())
	if err != nil {
		log.Printf("ping servers list error: %v", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}

	results := make([]ServerPingResult, len(servers))
	var wg sync.WaitGroup

	for i, s := range servers {
		wg.Add(1)
		go func(idx int, server models.VPNServer) {
			defer wg.Done()
			result := ServerPingResult{
				ServerID:    server.ID,
				Name:        server.Name,
				Host:        server.Host,
				Location:    server.Location,
				CountryCode: server.CountryCode,
			}

			healthURL, _, err := coreURL(&server, "/health")
			if err != nil {
				results[idx] = result
				return
			}
			start := time.Now()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
			if err != nil {
				results[idx] = result
				return
			}

			resp, err := coreHTTP.Do(req)
			elapsed := time.Since(start).Milliseconds()

			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					result.LatencyMs = elapsed
					result.Available = true
				}
			}

			results[idx] = result
		}(i, s)
	}
	wg.Wait()

	respond.JsonOK(w, results, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Connections — full VPN connection flow
// ═══════════════════════════════════════════════════════════════════════════

type ConnectRequest struct {
	ServerID   string `json:"server_id"`
	PublicKey  string `json:"public_key"`
	DeviceName string `json:"device_name"`
}

func (h *Handler) Connect(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	// 1. Validate banned
	if user.IsBanned {
		respond.JsonError(w, "account is banned", http.StatusForbidden)
		return
	}

	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		respond.JsonError(w, "public_key is required", http.StatusBadRequest)
		return
	}

	// 2. Enforce device limit
	if h.maxDevicesPerUser > 0 {
		activeCount, err := h.peerRepo.CountByUser(r.Context(), user.ID)
		if err != nil {
			log.Printf("count devices error: %v", err)
			respond.JsonError(w, "failed to check device limit", http.StatusInternalServerError)
			return
		}
		if activeCount >= h.maxDevicesPerUser {
			respond.JsonError(w, fmt.Sprintf("device limit reached (max %d)", h.maxDevicesPerUser), http.StatusConflict)
			return
		}
	}

	// 3. Select server (explicit or least loaded)
	var server *models.VPNServer
	if req.ServerID != "" {
		serverID, err := uuid.Parse(req.ServerID)
		if err != nil {
			respond.JsonError(w, "invalid server_id", http.StatusBadRequest)
			return
		}
		s, err := h.serverRepo.GetByID(r.Context(), serverID)
		if err != nil {
			respond.JsonError(w, "server not found", http.StatusNotFound)
			return
		}
		if !s.IsActive || s.CurrentPeers >= s.MaxPeers {
			respond.JsonError(w, "server is full or inactive", http.StatusConflict)
			return
		}
		server = s
	} else {
		s, err := h.serverRepo.LeastLoaded(r.Context())
		if err != nil {
			respond.JsonError(w, "no available servers", http.StatusServiceUnavailable)
			return
		}
		server = s
	}

	// 4+5. Call vpn-core to add peer (core assigns IP from pool)
	coreResp, err := CallCoreAddPeer(server, req.PublicKey)
	if err != nil {
		log.Printf("core add peer error: %v", err)
		respond.JsonError(w, "failed to connect to VPN server", http.StatusBadGateway)
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
		_ = CallCoreRemovePeer(server, req.PublicKey)
		log.Printf("create peer error: %v", err)
		respond.JsonError(w, "failed to save connection", http.StatusInternalServerError)
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

	respond.JsonOK(w, config, http.StatusCreated)
}

func (h *Handler) Disconnect(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	peerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	peer, err := h.peerRepo.GetByID(r.Context(), peerID)
	if err != nil {
		respond.JsonError(w, "peer not found", http.StatusNotFound)
		return
	}

	if peer.UserID != user.ID && !IsAdmin(user) {
		respond.JsonError(w, "not your peer", http.StatusForbidden)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err == nil {
		_ = CallCoreRemovePeer(server, peer.PublicKey)
		_ = h.serverRepo.UpdatePeerCount(r.Context(), peer.ServerID, -1)
	}

	_ = h.peerRepo.Deactivate(r.Context(), peerID)

	h.auditRepo.Log(r.Context(), &user.ID, "peer.disconnect",
		map[string]interface{}{"peer_id": peerID, "server_id": peer.ServerID}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"status": "disconnected"}, http.StatusOK)
}

func (h *Handler) ExportConfig(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	peerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	peer, err := h.peerRepo.GetByID(r.Context(), peerID)
	if err != nil {
		respond.JsonError(w, "peer not found", http.StatusNotFound)
		return
	}

	if peer.UserID != user.ID && !IsAdmin(user) {
		respond.JsonError(w, "not your peer", http.StatusForbidden)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err != nil {
		respond.JsonError(w, "server not found", http.StatusNotFound)
		return
	}

	conf := buildWGConfig(peer, server)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="wg-%s.conf"`, peer.DeviceName))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(conf))
}

func (h *Handler) ExportQR(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	peerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	peer, err := h.peerRepo.GetByID(r.Context(), peerID)
	if err != nil {
		respond.JsonError(w, "peer not found", http.StatusNotFound)
		return
	}

	if peer.UserID != user.ID && !IsAdmin(user) {
		respond.JsonError(w, "not your peer", http.StatusForbidden)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err != nil {
		respond.JsonError(w, "server not found", http.StatusNotFound)
		return
	}

	conf := buildWGConfig(peer, server)

	png, err := qrcode.Encode(conf, qrcode.Medium, 512)
	if err != nil {
		log.Printf("qr generation error: %v", err)
		respond.JsonError(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="wg-%s.png"`, peer.DeviceName))
	w.WriteHeader(http.StatusOK)
	w.Write(png)
}

func buildWGConfig(peer *models.Peer, server *models.VPNServer) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = <YOUR_PRIVATE_KEY>
Address = %s/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, peer.AssignedIP, server.PublicKey, server.Host, server.WGPort)
}

func (h *Handler) ListMyConnections(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	peers, err := h.peerRepo.ListByUser(r.Context(), user.ID)
	if err != nil {
		log.Printf("list connections error: %v", err)
		respond.JsonError(w, "failed to list connections", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, peers, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// User audit
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) MyAuditLogs(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	logs, err := h.auditRepo.ListByUser(r.Context(), user.ID, 50, 0)
	if err != nil {
		log.Printf("list audit logs error: %v", err)
		respond.JsonError(w, "failed to list audit logs", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, logs, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Admin API
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) AdminDashboardStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	totalUsers, _ := h.userRepo.Count(ctx)
	totalServers, activeServers, _ := h.serverRepo.Count(ctx)
	totalPeers, activePeers, _ := h.peerRepo.CountAll(ctx)
	bytesSent, bytesRecv, _ := h.peerRepo.TotalTraffic(ctx)

	stats := models.AdminStats{
		TotalUsers:     totalUsers,
		TotalServers:   totalServers,
		ActiveServers:  activeServers,
		TotalPeers:     totalPeers,
		ActivePeers:    activePeers,
		TotalBytesSent: bytesSent,
		TotalBytesRecv: bytesRecv,
	}
	respond.JsonOK(w, stats, http.StatusOK)
}

func (h *Handler) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationParams(r)
	users, err := h.userRepo.List(r.Context(), limit, offset)
	if err != nil {
		log.Printf("admin list users error: %v", err)
		respond.JsonError(w, "failed to list users", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, users, http.StatusOK)
}

func (h *Handler) AdminGetUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), id)
	if err != nil {
		respond.JsonError(w, "user not found", http.StatusNotFound)
		return
	}

	peers, _ := h.peerRepo.ListByUser(r.Context(), id)

	respond.JsonOK(w, map[string]interface{}{
		"user":  user,
		"peers": peers,
	}, http.StatusOK)
}

type AdminCreateUserRequest struct {
	AuthentikUID string   `json:"authentik_uid"`
	Email        string   `json:"email"`
	DisplayName  string   `json:"display_name"`
	Groups       []string `json:"groups"`
}

func (h *Handler) AdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req AdminCreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.AuthentikUID == "" || req.Email == "" {
		respond.JsonError(w, "authentik_uid and email are required", http.StatusBadRequest)
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
		log.Printf("admin create user error: %v", err)
		respond.JsonError(w, "failed to create user", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.create",
		map[string]interface{}{"target_user_id": user.ID}, r.RemoteAddr)

	respond.JsonOK(w, user, http.StatusCreated)
}

type AdminUpdateUserRequest struct {
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Groups      []string `json:"groups"`
}

func (h *Handler) AdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), id)
	if err != nil {
		respond.JsonError(w, "user not found", http.StatusNotFound)
		return
	}

	var req AdminUpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
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
		log.Printf("admin update user %s error: %v", user.ID, err)
		respond.JsonError(w, "failed to update user", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.update",
		map[string]interface{}{"target_user_id": id}, r.RemoteAddr)

	respond.JsonOK(w, user, http.StatusOK)
}

func (h *Handler) AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	admin := auth.GetUser(r)
	if admin.ID == id {
		respond.JsonError(w, "cannot delete your own account", http.StatusForbidden)
		return
	}

	if err := h.userRepo.Delete(r.Context(), id); err != nil {
		log.Printf("admin delete user %s error: %v", id, err)
		respond.JsonError(w, "failed to delete user", http.StatusInternalServerError)
		return
	}

	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.delete",
		map[string]interface{}{"target_user_id": id}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"deleted": id.String()}, http.StatusOK)
}

type BanRequest struct {
	Reason string `json:"reason"`
}

func (h *Handler) AdminBanUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	admin := auth.GetUser(r)
	if admin.ID == id {
		respond.JsonError(w, "cannot ban your own account", http.StatusForbidden)
		return
	}

	var req BanRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if err := h.userRepo.Ban(r.Context(), id, req.Reason); err != nil {
		log.Printf("admin ban user %s error: %v", id, err)
		respond.JsonError(w, "failed to ban user", http.StatusInternalServerError)
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
			_ = CallCoreRemovePeer(server, p.PublicKey)
			_ = h.serverRepo.UpdatePeerCount(r.Context(), p.ServerID, -1)
		}
		_ = h.peerRepo.Deactivate(r.Context(), p.ID)
	}

	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.ban",
		map[string]interface{}{"target_user_id": id, "reason": req.Reason}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"status": "banned"}, http.StatusOK)
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

func (h *Handler) AdminListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListAll(r.Context())
	if err != nil {
		log.Printf("admin list servers error: %v", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, servers, http.StatusOK)
}

func (h *Handler) AdminCreateServer(w http.ResponseWriter, r *http.Request) {
	var req CreateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Host == "" || req.PublicKey == "" || req.CoreToken == "" {
		respond.JsonError(w, "name, host, public_key and core_token are required", http.StatusBadRequest)
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
		PublicKey:   req.PublicKey,
		CoreToken:   req.CoreToken,
		Location:    req.Location,
		CountryCode: req.CountryCode,
		MaxPeers:    req.MaxPeers,
	}

	if err := h.serverRepo.Create(r.Context(), server); err != nil {
		log.Printf("admin create server error: %v", err)
		respond.JsonError(w, "failed to create server", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.server.create",
		map[string]interface{}{"server_id": server.ID, "name": server.Name}, r.RemoteAddr)

	respond.JsonOK(w, server, http.StatusCreated)
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

func (h *Handler) AdminUpdateServer(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid server id", http.StatusBadRequest)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), id)
	if err != nil {
		respond.JsonError(w, "server not found", http.StatusNotFound)
		return
	}

	var req UpdateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
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
		log.Printf("admin update server %s error: %v", server.ID, err)
		respond.JsonError(w, "failed to update server", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.server.update",
		map[string]interface{}{"server_id": id}, r.RemoteAddr)

	respond.JsonOK(w, server, http.StatusOK)
}

func (h *Handler) AdminDeleteServer(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid server id", http.StatusBadRequest)
		return
	}

	if err := h.serverRepo.Delete(r.Context(), id); err != nil {
		log.Printf("admin delete server %s error: %v", id, err)
		respond.JsonError(w, "failed to delete server", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.server.delete",
		map[string]interface{}{"server_id": id}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"deleted": id.String()}, http.StatusOK)
}

func (h *Handler) AdminListPeers(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationParams(r)
	peers, err := h.peerRepo.ListAll(r.Context(), limit, offset)
	if err != nil {
		log.Printf("admin list peers error: %v", err)
		respond.JsonError(w, "failed to list peers", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, peers, http.StatusOK)
}

func (h *Handler) AdminForceDisconnectPeer(w http.ResponseWriter, r *http.Request) {
	peerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	peer, err := h.peerRepo.GetByID(r.Context(), peerID)
	if err != nil {
		respond.JsonError(w, "peer not found", http.StatusNotFound)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err == nil {
		_ = CallCoreRemovePeer(server, peer.PublicKey)
		_ = h.serverRepo.UpdatePeerCount(r.Context(), peer.ServerID, -1)
	}

	_ = h.peerRepo.Deactivate(r.Context(), peerID)

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.peer.disconnect",
		map[string]interface{}{"peer_id": peerID, "user_id": peer.UserID}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"status": "disconnected"}, http.StatusOK)
}

func (h *Handler) AdminListAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationParams(r)
	action := r.URL.Query().Get("action")
	logs, err := h.auditRepo.ListAll(r.Context(), limit, offset, action)
	if err != nil {
		log.Printf("admin list audit logs error: %v", err)
		respond.JsonError(w, "failed to list audit logs", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, logs, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

func IsAdmin(user *models.User) bool {
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
		if !IsAdmin(user) {
			respond.JsonError(w, "admin access required", http.StatusForbidden)
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

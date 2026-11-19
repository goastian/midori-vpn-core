package control

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

// ═══════════════════════════════════════════════════════════════════════════
// Admin API
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) AdminDashboardStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.dashboardRepo.Infrastructure(r.Context())
	if err != nil {
		respond.SafeError(w, "failed to load dashboard statistics", err, http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, stats, http.StatusOK)
}

func (h *Handler) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	query, ok := requirePageQuery(w, r, pageQueryConfig{
		DefaultSort: "created_at",
		Sorts:       []string{"created_at", "email", "display_name"},
		Statuses:    []string{"all", "active", "banned"},
		AllowSearch: true,
	})
	if !ok {
		return
	}
	users, total, err := h.userRepo.ListAdminPage(r.Context(), query.ListOptions())
	if err != nil {
		slog.Error("admin list users error", "error", err)
		respond.JsonError(w, "failed to list users", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, newPageResponse(users, query, total), http.StatusOK)
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

	query, ok := requirePageQuery(w, r, pageQueryConfig{
		DefaultSort: "created_at",
		Sorts:       []string{"created_at", "last_handshake", "traffic"},
		Statuses:    []string{"all", "active", "inactive"},
		AllowSearch: true,
	})
	if !ok {
		return
	}
	peers, total, err := h.peerRepo.ListAdminPage(r.Context(), repo.AdminPeerListOptions{
		ListOptions: query.ListOptions(),
		UserID:      &id,
	})
	if err != nil {
		respond.SafeError(w, "failed to list user sessions", err, http.StatusInternalServerError)
		return
	}

	respond.JsonOK(w, map[string]interface{}{
		"user":  user,
		"peers": newPageResponse(peers, query, total),
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
		slog.Error("admin create user error", "error", err)
		respond.JsonError(w, "failed to create user", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, "admin.user.create",
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
		slog.Error("admin update user error", "user_id", user.ID, "error", err)
		respond.JsonError(w, "failed to update user", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, "admin.user.update",
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

	if err := h.userRepo.DeleteIfDrained(r.Context(), id); err != nil {
		if errors.Is(err, repo.ErrActiveDevicesMustBeDisconnected) {
			respond.JsonErrorCode(w, "active devices must be disconnected before deleting the user", "active_devices_must_be_disconnected", http.StatusConflict)
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "user not found", http.StatusNotFound)
			return
		}
		slog.Error("admin delete user error", "user_id", id, "error", err)
		respond.JsonError(w, "failed to delete user", http.StatusInternalServerError)
		return
	}

	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, "admin.user.delete",
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.userRepo.Ban(r.Context(), id, req.Reason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "user not found", http.StatusNotFound)
			return
		}
		slog.Error("admin ban user error", "user_id", id, "error", err)
		respond.JsonError(w, "failed to ban user", http.StatusInternalServerError)
		return
	}

	cleanupPending := false
	peers, listErr := h.peerRepo.ListActiveByUser(r.Context(), id)
	if listErr != nil {
		cleanupPending = true
		slog.Error("banned user cleanup could not list sessions", "user_id", id, "error", listErr)
	} else {
		for index := range peers {
			outcome, disconnectErr := h.disconnectPeer(r.Context(), peers[index].ID)
			if disconnectErr != nil || !outcome.Converged {
				cleanupPending = true
				if disconnectErr != nil && !errors.Is(disconnectErr, repo.ErrConnectionInProgress) {
					slog.Error("banned user cleanup could not be scheduled", "user_id", id, "peer_id", peers[index].ID, "error", disconnectErr)
				}
			}
		}
	}
	if liveOperation, operationErr := h.peerOperationRepo.HasLiveByUser(r.Context(), id); operationErr != nil {
		cleanupPending = true
		slog.Error("banned user cleanup state could not be verified", "user_id", id, "error", operationErr)
	} else if liveOperation {
		cleanupPending = true
	}

	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, "admin.user.ban",
		map[string]interface{}{"target_user_id": id, "reason": req.Reason}, r.RemoteAddr)

	if cleanupPending {
		w.Header().Set("Retry-After", "5")
		respondStatus(w, "ban_cleanup_pending", http.StatusAccepted)
		return
	}
	respondStatus(w, "banned", http.StatusOK)
}

func (h *Handler) AdminUnbanUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	if err := h.userRepo.Unban(r.Context(), id); err != nil {
		slog.Error("admin unban user error", "user_id", id, "error", err)
		respond.JsonError(w, "failed to unban user", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, "admin.user.unban",
		map[string]interface{}{"target_user_id": id}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"status": "unbanned"}, http.StatusOK)
}

type CreateServerRequest struct {
	Name        string             `json:"name"`
	Host        string             `json:"host"`
	ProbeURL    string             `json:"probe_url"`
	Endpoint    string             `json:"endpoint"`
	Port        int                `json:"port"`
	WGPort      int                `json:"wg_port"`
	PublicKey   string             `json:"public_key"`
	Location    string             `json:"location"`
	CountryCode string             `json:"country_code"`
	MaxPeers    int                `json:"max_peers"`
	Transports  []TransportRequest `json:"transports"`
}

func (h *Handler) AdminListServers(w http.ResponseWriter, r *http.Request) {
	query, ok := requirePageQuery(w, r, pageQueryConfig{
		DefaultSort: "name",
		Sorts:       []string{"name", "created_at", "current_peers"},
		Statuses:    []string{"all", "active", "inactive", "draining"},
		AllowSearch: true,
	})
	if !ok {
		return
	}
	servers, total, err := h.serverRepo.ListAdminPage(r.Context(), query.ListOptions())
	if err != nil {
		slog.Error("admin list servers error", "error", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, newPageResponse(servers, query, total), http.StatusOK)
}

func (h *Handler) AdminListNodeIdentities(w http.ResponseWriter, r *http.Request) {
	if h.nodeVerifier == nil {
		respond.JsonError(w, "node identity registry is unavailable", http.StatusServiceUnavailable)
		return
	}
	query, ok := requirePageQuery(w, r, pageQueryConfig{
		DefaultSort: "node_id",
		Sorts:       []string{"node_id", "source"},
		Statuses:    []string{"all", "active", "revoked"},
		AllowSearch: true,
	})
	if !ok {
		return
	}
	identities, err := h.nodeVerifier.List(r.Context())
	if err != nil {
		respond.JsonError(w, "failed to list node identities", http.StatusServiceUnavailable)
		return
	}
	items, total := paginateNodeIdentities(identities, query)
	respond.JsonOK(w, newPageResponse(items, query, total), http.StatusOK)
}

func (h *Handler) AdminRegisterNodeIdentity(w http.ResponseWriter, r *http.Request) {
	if h.nodeVerifier == nil {
		respond.JsonError(w, "node identity registry is unavailable", http.StatusServiceUnavailable)
		return
	}
	var request struct {
		NodeID    string `json:"node_id"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := h.nodeVerifier.Register(r.Context(), request.NodeID, request.PublicKey); err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	admin := auth.GetUser(r)
	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, "admin.node-identity.register", map[string]interface{}{"node_id": request.NodeID}, r.RemoteAddr)
	respond.JsonOK(w, map[string]string{"node_id": request.NodeID, "status": "registered"}, http.StatusCreated)
}

func (h *Handler) AdminRevokeNodeIdentity(w http.ResponseWriter, r *http.Request) {
	h.changeNodeIdentityRevocation(w, r, true)
}

func (h *Handler) AdminRestoreNodeIdentity(w http.ResponseWriter, r *http.Request) {
	h.changeNodeIdentityRevocation(w, r, false)
}

func (h *Handler) changeNodeIdentityRevocation(w http.ResponseWriter, r *http.Request, revoked bool) {
	if h.nodeVerifier == nil {
		respond.JsonError(w, "node identity registry is unavailable", http.StatusServiceUnavailable)
		return
	}
	nodeID := strings.TrimSpace(chi.URLParam(r, "nodeID"))
	if nodeID == "" {
		respond.JsonError(w, "node_id is required", http.StatusBadRequest)
		return
	}
	status := "restored"
	action := "admin.node-identity.restore"
	var err error
	if revoked {
		err = h.nodeVerifier.Revoke(r.Context(), nodeID)
		status = "revoked"
		action = "admin.node-identity.revoke"
	} else {
		err = h.nodeVerifier.Restore(r.Context(), nodeID)
	}
	if err != nil {
		respond.JsonError(w, "failed to update node identity", http.StatusServiceUnavailable)
		return
	}
	admin := auth.GetUser(r)
	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, action, map[string]interface{}{"node_id": nodeID}, r.RemoteAddr)
	respond.JsonOK(w, map[string]string{"node_id": nodeID, "status": status}, http.StatusOK)
}

func (h *Handler) AdminCreateServer(w http.ResponseWriter, r *http.Request) {
	var req CreateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Host == "" || req.PublicKey == "" || req.ProbeURL == "" {
		respond.JsonError(w, "name, host, probe_url and public_key are required", http.StatusBadRequest)
		return
	}
	probeURL, err := normalizeProbeURL(req.ProbeURL)
	if err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ProbeURL = probeURL
	if req.Port == 0 {
		req.Port = defaultAdminServerPort(h.coreAllowLoopback)
	}
	if req.WGPort == 0 {
		req.WGPort = 51820
	}
	if req.MaxPeers == 0 {
		req.MaxPeers = 250
	}

	// Validate optional WireGuard endpoint (public IP or hostname used in client configs).
	if req.Endpoint != "" {
		if err := validateServerEndpoint(req.Endpoint); err != nil {
			respond.JsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	normalizedHost, normalizedPort, err := normalizeAdminServerHost(req.Host, req.Port)
	if err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Host = normalizedHost
	req.Port = normalizedPort
	if h.appEnv == "production" && !h.coreAllowLoopback && isLoopbackServerHost(req.Host) {
		respond.JsonError(w, "loopback hosts (localhost/127.0.0.1/::1) are not allowed in production — set CORE_ALLOW_INSECURE_HTTP=true to override", http.StatusBadRequest)
		return
	}
	if h.appEnv == "production" && !h.coreAllowLoopback {
		parsedProbe, _ := url.Parse(req.ProbeURL)
		if isLoopbackServerHost(parsedProbe.Hostname()) {
			respond.JsonError(w, "loopback probe URLs are not allowed in production", http.StatusBadRequest)
			return
		}
	}

	server := &models.VPNServer{
		Name:        req.Name,
		Host:        req.Host,
		ProbeURL:    req.ProbeURL,
		Endpoint:    req.Endpoint,
		Port:        req.Port,
		WGPort:      req.WGPort,
		PublicKey:   req.PublicKey,
		Location:    req.Location,
		CountryCode: req.CountryCode,
		MaxPeers:    req.MaxPeers,
		IsActive:    true,
	}
	if req.Transports == nil {
		respond.JsonError(w, "transports is required", http.StatusBadRequest)
		return
	}
	transports, err := validateTransportRequests(req.Transports, h.appEnv == "production", h.coreAllowLoopback)
	if err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if hasEnabledCertificateTransport(transports) && h.clientCertificateCA == nil {
		respond.JsonErrorCode(w, "client PKI must be configured before enabling OpenVPN or IKEv2", clientPKIUnavailableCode, http.StatusConflict)
		return
	}

	if err := h.serverRepo.CreateWithTransports(r.Context(), server, transports); err != nil {
		slog.Error("admin create server error", "error", err)
		respond.JsonError(w, "failed to create server", http.StatusInternalServerError)
		return
	}
	server.SetTransports(transports)
	server.ApplyCapabilities()

	admin := auth.GetUser(r)
	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, "admin.server.create",
		map[string]interface{}{"server_id": server.ID, "name": server.Name}, r.RemoteAddr)

	respond.JsonOK(w, server, http.StatusCreated)
}

type UpdateServerRequest struct {
	Name        string              `json:"name"`
	Host        string              `json:"host"`
	ProbeURL    *string             `json:"probe_url"`
	Endpoint    string              `json:"endpoint"`
	Port        int                 `json:"port"`
	WGPort      int                 `json:"wg_port"`
	PublicKey   string              `json:"public_key"`
	Location    string              `json:"location"`
	CountryCode string              `json:"country_code"`
	MaxPeers    int                 `json:"max_peers"`
	IsActive    *bool               `json:"is_active"`
	Transports  *[]TransportRequest `json:"transports"`
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
	if req.ProbeURL != nil {
		probeURL, err := normalizeProbeURL(*req.ProbeURL)
		if err != nil {
			respond.JsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if h.appEnv == "production" && !h.coreAllowLoopback {
			parsedProbe, _ := url.Parse(probeURL)
			if isLoopbackServerHost(parsedProbe.Hostname()) {
				respond.JsonError(w, "loopback probe URLs are not allowed in production", http.StatusBadRequest)
				return
			}
		}
		server.ProbeURL = probeURL
	}
	// Endpoint may be cleared (set to "") intentionally, so always update it.
	// Validate if non-empty.
	if req.Endpoint != "" {
		if err := validateServerEndpoint(req.Endpoint); err != nil {
			respond.JsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	server.Endpoint = req.Endpoint
	if req.Host != "" || req.Port != 0 {
		hostInput := server.Host
		if req.Host != "" {
			hostInput = req.Host
		}
		portInput := server.Port
		if req.Port != 0 {
			portInput = req.Port
		}

		normalizedHost, normalizedPort, err := normalizeAdminServerHost(hostInput, portInput)
		if err != nil {
			respond.JsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if h.appEnv == "production" && !h.coreAllowLoopback && isLoopbackServerHost(normalizedHost) {
			respond.JsonError(w, "loopback hosts (localhost/127.0.0.1/::1) are not allowed in production — set CORE_ALLOW_INSECURE_HTTP=true to override", http.StatusBadRequest)
			return
		}

		server.Host = normalizedHost
		server.Port = normalizedPort
	}
	if req.WGPort != 0 {
		server.WGPort = req.WGPort
	}
	if req.PublicKey != "" {
		server.PublicKey = req.PublicKey
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
		if server.IsActive {
			server.DrainingAt = nil
		}
	}
	var transports []models.TransportCapability
	if req.Transports != nil {
		transports, err = validateTransportRequests(*req.Transports, h.appEnv == "production", h.coreAllowLoopback)
		if err != nil {
			respond.JsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if hasEnabledCertificateTransport(transports) && h.clientCertificateCA == nil {
			respond.JsonErrorCode(w, "client PKI must be configured before enabling OpenVPN or IKEv2", clientPKIUnavailableCode, http.StatusConflict)
			return
		}
	}

	if err := h.serverRepo.UpdateWithTransports(r.Context(), server, transports, req.Transports != nil); err != nil {
		slog.Error("admin update server error", "server_id", server.ID, "error", err)
		respond.JsonError(w, "failed to update server", http.StatusInternalServerError)
		return
	}
	if req.Transports != nil {
		server.SetTransports(transports)
	}
	server.ApplyCapabilities()

	admin := auth.GetUser(r)
	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, "admin.server.update",
		map[string]interface{}{"server_id": id}, r.RemoteAddr)

	respond.JsonOK(w, server, http.StatusOK)
}

func (h *Handler) AdminDeleteServer(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid server id", http.StatusBadRequest)
		return
	}

	if err := h.serverRepo.DrainAndDelete(r.Context(), id); err != nil {
		if errors.Is(err, repo.ErrServerNotDrained) {
			respond.JsonErrorCode(w, "server is draining and still has active sessions or operations", "server_not_drained", http.StatusConflict)
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "server not found", http.StatusNotFound)
			return
		}
		slog.Error("admin delete server error", "server_id", id, "error", err)
		respond.JsonError(w, "failed to delete server", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, "admin.server.delete",
		map[string]interface{}{"server_id": id}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"deleted": id.String()}, http.StatusOK)
}

func (h *Handler) AdminListPeers(w http.ResponseWriter, r *http.Request) {
	query, ok := requirePageQuery(w, r, pageQueryConfig{
		DefaultSort: "created_at",
		Sorts:       []string{"created_at", "last_handshake", "traffic"},
		Statuses:    []string{"all", "active", "inactive"},
		AllowSearch: true,
	})
	if !ok {
		return
	}
	peers, total, err := h.peerRepo.ListAdminPage(r.Context(), repo.AdminPeerListOptions{
		ListOptions: query.ListOptions(),
	})
	if err != nil {
		slog.Error("admin list peers error", "error", err)
		respond.JsonError(w, "failed to list peers", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, newPageResponse(peers, query, total), http.StatusOK)
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

	outcome, err := h.disconnectPeer(r.Context(), peerID)
	if errors.Is(err, repo.ErrConnectionInProgress) {
		w.Header().Set("Retry-After", "5")
		respond.JsonErrorCode(w, "connection operation is still in progress", "connection_in_progress", http.StatusConflict)
		return
	}
	if err != nil {
		slog.Error("admin disconnect could not be scheduled", "peer_id", peerID, "error", err)
		respond.JsonError(w, "failed to disconnect peer", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.LogBestEffort(r.Context(), &admin.ID, "admin.peer.disconnect",
		map[string]interface{}{"peer_id": peerID, "user_id": peer.UserID}, r.RemoteAddr)

	respondDisconnect(w, outcome, "disconnect_pending")
}

func (h *Handler) AdminListAuditLogs(w http.ResponseWriter, r *http.Request) {
	query, ok := requirePageQuery(w, r, pageQueryConfig{
		DefaultSort: "created_at",
		Sorts:       []string{"created_at", "action"},
		Statuses:    []string{"all"},
		AllowSearch: true,
		Extras:      []string{"action"},
	})
	if !ok {
		return
	}
	logs, total, err := h.auditRepo.ListAdminPage(r.Context(), repo.AdminAuditListOptions{
		ListOptions: query.ListOptions(),
		Action:      query.Extras["action"],
	})
	if err != nil {
		slog.Error("admin list audit logs error", "error", err)
		respond.JsonError(w, "failed to list audit logs", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, newPageResponse(logs, query, total), http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

func IsAdmin(user *models.User) bool {
	if user == nil {
		return false
	}
	for _, g := range user.Groups {
		switch g {
		case "vpn-admins":
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

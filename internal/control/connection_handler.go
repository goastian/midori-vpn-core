package control

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/goastian/midori-vpn-core/internal/auth"
	vpnCrypto "github.com/goastian/midori-vpn-core/internal/crypto"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/proxytoken"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

// ═══════════════════════════════════════════════════════════════════════════
// Connections — full VPN connection flow
// ═══════════════════════════════════════════════════════════════════════════

type ConnectRequest struct {
	ServerID         string                  `json:"server_id"`
	PublicKey        string                  `json:"public_key"`
	DeviceName       string                  `json:"device_name"`
	Device           *DeviceRequest          `json:"device,omitempty"`
	ConnectionReason models.ConnectionReason `json:"connection_reason,omitempty"`
	PQKEMPublicKey   string                  `json:"pq_kem_public_key,omitempty"`
}

func (h *Handler) respondWithExistingConnection(w http.ResponseWriter, r *http.Request, peer *models.Peer, pqCiphertext string, status int) {
	if peer.DeviceID == nil {
		respond.JsonError(w, "active connection has no device identity", http.StatusInternalServerError)
		return
	}
	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err != nil {
		respond.SafeError(w, "failed to load connection server", err, http.StatusInternalServerError)
		return
	}
	wireGuard, configured := enabledServerTransport(server, "wireguard")
	if !configured {
		respond.JsonError(w, "the existing server no longer has WireGuard enabled", http.StatusConflict)
		return
	}
	serverPublicKey := server.PublicKey
	if coreStats, statsErr := CallCoreServerStats(server); statsErr == nil && coreStats.PublicKey != "" {
		serverPublicKey = coreStats.PublicKey
		if server.PublicKey != coreStats.PublicKey {
			server.PublicKey = coreStats.PublicKey
			if updateErr := h.serverRepo.Update(r.Context(), server); updateErr != nil {
				slog.Warn("failed to persist server public key", "server_id", server.ID, "error", updateErr)
			}
		}
	}
	peerIP := peer.AssignedIP
	if index := strings.Index(peerIP, "/"); index != -1 {
		peerIP = peerIP[:index]
	}
	w.Header().Set("Cache-Control", "no-store")
	respond.JsonOK(w, models.ConnectionConfig{
		PeerID:          peer.ID,
		DeviceID:        *peer.DeviceID,
		PeerIP:          peerIP,
		ServerPublicKey: serverPublicKey,
		ServerEndpoint:  wireGuardEndpointForServerHost(wireGuard.Host, wireGuard.Port),
		PresharedKey:    peer.PresharedKey,
		PQKEMCiphertext: pqCiphertext,
		DNS:             h.vpnDNS,
		AllowedIPs:      "0.0.0.0/0, ::/0",
	}, status)
}

func (h *Handler) Connect(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	// Per-user rate limit: prevent connection-spam / brute-force reconnects.
	if h.connectLimiter != nil && !h.connectLimiter.Allow(user.ID.String()) {
		respond.JsonError(w, "too many connection requests — please wait before trying again", http.StatusTooManyRequests)
		return
	}

	var req ConnectRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		respond.JsonError(w, "public_key is required", http.StatusBadRequest)
		return
	}
	if !isValidWGKey(req.PublicKey) {
		respond.JsonError(w, "public_key must be a valid 32-byte base64-encoded WireGuard key", http.StatusBadRequest)
		return
	}
	if req.ConnectionReason == "" {
		req.ConnectionReason = models.ConnectionReasonUser
	}
	if !req.ConnectionReason.Valid() {
		respond.JsonError(w, "connection_reason must be user or automatic_failover", http.StatusBadRequest)
		return
	}
	deviceRequest, err := normalizeDeviceRequest(req.Device, req.DeviceName)
	if err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var device *models.Device
	if deviceRequest.clientInstanceID != nil {
		device, err = h.resolveRegisteredDevice(r.Context(), user.ID, deviceRequest)
		if errors.Is(err, repo.ErrDeviceRevoked) {
			respond.JsonErrorCode(w, "device is revoked", "device_revoked", http.StatusConflict)
			return
		}
		if err != nil {
			respond.SafeError(w, "failed to resolve device identity", err, http.StatusInternalServerError)
			return
		}
	}

	// Recognize durable retries before quota or capacity checks. An unfinished
	// operation must be reconciled rather than duplicated; a finished operation
	// returns the exact session and sensitive material already persisted for it.
	if operation, existingPeer, findErr := h.peerOperationRepo.FindCurrentByKey(r.Context(), user.ID, req.PublicKey); findErr == nil {
		if existingPeer == nil {
			w.Header().Set("Retry-After", "5")
			respond.JsonErrorCode(w, "connection operation is still in progress", "connection_in_progress", http.StatusConflict)
			return
		}
		if device != nil && (existingPeer.DeviceID == nil || *existingPeer.DeviceID != device.ID) {
			respond.JsonErrorCode(w, "public key belongs to another device", "peer_operation_conflict", http.StatusConflict)
			return
		}
		h.respondWithExistingConnection(w, r, existingPeer, operation.PQKEMCiphertext, http.StatusOK)
		return
	} else if !errors.Is(findErr, pgx.ErrNoRows) {
		respond.SafeError(w, "failed to inspect connection operation", findErr, http.StatusInternalServerError)
		return
	}

	// Compatibility for active peers created before operation persistence.
	if existingPeer, err := h.peerRepo.GetActiveByUserAndPublicKey(r.Context(), user.ID, req.PublicKey); err == nil {
		if existingPeer.DeviceID == nil {
			respond.JsonError(w, "active connection has no device identity", http.StatusInternalServerError)
			return
		}
		if device != nil && *existingPeer.DeviceID != device.ID {
			respond.JsonErrorCode(w, "public key belongs to another device", "peer_operation_conflict", http.StatusConflict)
			return
		}
		h.respondWithExistingConnection(w, r, existingPeer, "", http.StatusOK)
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		respond.SafeError(w, "failed to inspect active connection", err, http.StatusInternalServerError)
		return
	}

	// 2. Enforce global user device limit based on plan/quota
	userQuota, err := h.getUserQuota(r.Context(), user)
	if err != nil {
		respond.SafeError(w, "failed to load device quota", err, http.StatusInternalServerError)
		return
	}
	replacesActiveDevice := false
	if device != nil {
		replacesActiveDevice, err = h.deviceRepo.HasActiveSession(r.Context(), user.ID, device.ID)
		if err != nil {
			respond.SafeError(w, "failed to check active device session", err, http.StatusInternalServerError)
			return
		}
	}
	if userQuota.ConnectedDevices >= userQuota.MaxDevices && !replacesActiveDevice {
		respond.JsonErrorCode(w, fmt.Sprintf("device limit reached (%d/%d devices in use on your %s)", userQuota.ConnectedDevices, userQuota.MaxDevices, userQuota.PlanName), "device_limit_reached", http.StatusConflict)
		return
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
			slog.Error("serverRepo.GetByID error", "server_id", serverID, "error", err)
			if errors.Is(err, pgx.ErrNoRows) {
				respond.JsonError(w, "server not found", http.StatusNotFound)
			} else {
				respond.JsonError(w, "failed to get server", http.StatusInternalServerError)
			}
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
	_, configured := enabledServerTransport(server, "wireguard")
	if !configured {
		respond.JsonError(w, "selected server does not have WireGuard enabled", http.StatusConflict)
		return
	}

	// 4. Generate post-quantum resistant Pre-Shared Key (PSK) or ML-KEM-768 encapsulation
	var psk string
	var pqCiphertext string
	if req.PQKEMPublicKey != "" {
		var kemErr error
		psk, pqCiphertext, kemErr = vpnCrypto.EncapsulateSharedKey(req.PQKEMPublicKey)
		if kemErr != nil {
			slog.Warn("ML-KEM-768 encapsulation failed, falling back to symmetric PSK", "error", kemErr)
			psk, _ = vpnCrypto.GeneratePresharedKey()
		}
	} else {
		var pskErr error
		psk, pskErr = vpnCrypto.GeneratePresharedKey()
		if pskErr != nil {
			slog.Warn("failed to generate PSK", "error", pskErr)
		}
	}

	operationID := uuid.New()
	beginResult, err := h.peerOperationRepo.BeginConnect(r.Context(), repo.BeginConnectParams{
		OperationID:      operationID,
		UserID:           user.ID,
		Device:           device,
		LegacyDeviceName: deviceRequest.reportedName,
		ServerID:         server.ID,
		PublicKey:        req.PublicKey,
		ConnectionReason: req.ConnectionReason,
		PresharedKey:     psk,
		PQKEMCiphertext:  pqCiphertext,
		MaxDevices:       userQuota.MaxDevices,
	})
	if err != nil {
		switch {
		case errors.Is(err, repo.ErrConnectionInProgress):
			w.Header().Set("Retry-After", "5")
			respond.JsonErrorCode(w, "connection operation is still in progress", "connection_in_progress", http.StatusConflict)
		case errors.Is(err, repo.ErrDeviceLimitReached):
			respond.JsonErrorCode(w, fmt.Sprintf("device limit reached (%d devices on your %s)", userQuota.MaxDevices, userQuota.PlanName), "device_limit_reached", http.StatusConflict)
		case errors.Is(err, repo.ErrServerCapacity):
			respond.JsonError(w, "server is full or inactive", http.StatusConflict)
		case errors.Is(err, repo.ErrServerPlacement):
			respond.JsonError(w, "server node is not ready for new connections", http.StatusConflict)
		case errors.Is(err, repo.ErrDeviceRevoked):
			respond.JsonErrorCode(w, "device is revoked", "device_revoked", http.StatusConflict)
		case errors.Is(err, repo.ErrPeerOperationConflict):
			respond.JsonErrorCode(w, "public key belongs to another device", "peer_operation_conflict", http.StatusConflict)
		default:
			respond.SafeError(w, "failed to start connection operation", err, http.StatusInternalServerError)
		}
		return
	}
	if beginResult.ExistingPeer != nil {
		pqCiphertext := ""
		if beginResult.Operation != nil {
			pqCiphertext = beginResult.Operation.PQKEMCiphertext
		}
		h.respondWithExistingConnection(w, r, beginResult.ExistingPeer, pqCiphertext, http.StatusOK)
		return
	}
	h.serverRepo.InvalidateCache()
	device = beginResult.Device

	// Peers created before Control persisted operations still have an exact
	// owner in Core (assigned during Core's legacy-state adoption). Capture that
	// owner before applying the replacement so delayed cleanup can never target
	// whichever operation happens to own the key later.
	if beginResult.PreviousPeer != nil && beginResult.Operation.PreviousOperationID == nil {
		previousServer, loadErr := h.serverRepo.GetByID(r.Context(), beginResult.PreviousPeer.ServerID)
		if loadErr != nil {
			_ = h.peerOperationRepo.FailDefinitively(r.Context(), operationID, loadErr)
			h.serverRepo.InvalidateCache()
			respond.SafeError(w, "failed to load previous connection server", loadErr, http.StatusInternalServerError)
			return
		}
		previousStats, observeErr := CallCoreGetPeerStats(previousServer, beginResult.PreviousPeer.PublicKey)
		if coreErrorHasStatus(observeErr, http.StatusNotFound) {
			// The database row is stale and there is no Core peer to clean up.
		} else if observeErr != nil {
			_ = h.peerOperationRepo.FailDefinitively(r.Context(), operationID, observeErr)
			h.serverRepo.InvalidateCache()
			respond.JsonError(w, "failed to verify previous VPN session", http.StatusBadGateway)
			return
		} else {
			previousOperationID, parseErr := uuid.Parse(previousStats.OperationID)
			if parseErr != nil || previousOperationID == uuid.Nil {
				identityErr := errors.New("previous Core peer has an invalid operation identity")
				_ = h.peerOperationRepo.FailDefinitively(r.Context(), operationID, identityErr)
				h.serverRepo.InvalidateCache()
				respond.JsonError(w, "failed to verify previous VPN session", http.StatusBadGateway)
				return
			}
			if setErr := h.peerOperationRepo.SetPreviousOperationID(r.Context(), operationID, previousOperationID); setErr != nil {
				_ = h.peerOperationRepo.FailDefinitively(r.Context(), operationID, setErr)
				h.serverRepo.InvalidateCache()
				respond.SafeError(w, "failed to persist previous connection owner", setErr, http.StatusInternalServerError)
				return
			}
			beginResult.Operation.PreviousOperationID = &previousOperationID
		}
	}

	coreResp, err := CallCoreAddPeer(server, req.PublicKey, operationID.String(), psk)
	if err != nil {
		slog.Error("core add peer error", "error", err)
		var coreError *CoreAPIError
		if errors.As(err, &coreError) && coreError.Status >= 400 && coreError.Status < 500 {
			if failErr := h.peerOperationRepo.FailDefinitively(r.Context(), operationID, err); failErr != nil {
				slog.Error("failed to finalize rejected peer operation", "operation_id", operationID, "error", failErr)
			}
			h.serverRepo.InvalidateCache()
			if coreError.Code == "peer_operation_conflict" {
				respond.JsonErrorCode(w, "peer is owned by another operation", "peer_operation_conflict", http.StatusConflict)
				return
			}
		}
		respond.JsonError(w, "failed to connect to VPN server", http.StatusBadGateway)
		return
	}
	if err := h.peerOperationRepo.MarkCoreApplied(r.Context(), operationID, coreResp.AllowedIP); err != nil {
		slog.Error("failed to persist applied Core operation", "operation_id", operationID, "error", err)
		respond.JsonError(w, "failed to persist connection progress", http.StatusInternalServerError)
		return
	}
	peer, previousPeer, err := h.peerOperationRepo.CompleteConnect(r.Context(), operationID)
	if err != nil {
		if errors.Is(err, repo.ErrAccessRevoked) {
			cleanupErr := CallCoreRemovePeerContext(r.Context(), server, req.PublicKey, operationID.String())
			if cleanupErr == nil {
				cleanupErr = h.peerOperationRepo.CancelDeniedConnect(r.Context(), operationID)
			}
			if cleanupErr != nil {
				h.recordDisconnectFailure(r.Context(), operationID, cleanupErr)
			}
			respond.JsonError(w, "account or device access was revoked", http.StatusForbidden)
			return
		}
		slog.Error("failed to complete peer operation", "operation_id", operationID, "error", err)
		respond.JsonError(w, "failed to save connection", http.StatusInternalServerError)
		return
	}
	h.serverRepo.InvalidateCache()

	if previousPeer != nil && previousPeer.IsActive {
		if beginResult.Operation.PreviousOperationID == nil {
			// The preflight observation already proved the legacy Core peer absent.
			_ = h.peerOperationRepo.CompleteCleanup(r.Context(), operationID)
		} else {
			previousServer, loadErr := h.serverRepo.GetByID(r.Context(), previousPeer.ServerID)
			if loadErr != nil {
				_ = h.peerOperationRepo.MarkCleanupPending(r.Context(), operationID, loadErr)
			} else {
				cleanupErr := CallCoreRemovePeer(previousServer, previousPeer.PublicKey, beginResult.Operation.PreviousOperationID.String())
				if cleanupErr != nil {
					slog.Error("replaced peer cleanup is pending", "operation_id", operationID, "peer_id", previousPeer.ID, "error", cleanupErr)
					_ = h.peerOperationRepo.MarkCleanupPending(r.Context(), operationID, cleanupErr)
				} else if completeErr := h.peerOperationRepo.CompleteCleanup(r.Context(), operationID); completeErr != nil {
					slog.Error("failed to finalize replaced peer cleanup", "operation_id", operationID, "peer_id", previousPeer.ID, "error", completeErr)
				}
			}
		}
	}

	h.attachPeerToMeshSessions(r.Context(), user.ID, peer)

	h.auditRepo.Log(r.Context(), &user.ID, "peer.connect",
		map[string]interface{}{
			"operation_id": operationID,
			"peer_id":      peer.ID,
			"device_id":    device.ID,
			"server_id":    server.ID,
			"ip":           peer.AssignedIP,
			"device_name":  device.ReportedName,
			"psk_enabled":  psk != "",
		}, r.RemoteAddr)

	h.respondWithExistingConnection(w, r, peer, pqCiphertext, http.StatusCreated)
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

	outcome, err := h.disconnectPeer(r.Context(), peerID)
	if errors.Is(err, repo.ErrConnectionInProgress) {
		w.Header().Set("Retry-After", "5")
		respond.JsonErrorCode(w, "connection operation is still in progress", "connection_in_progress", http.StatusConflict)
		return
	}
	if err != nil {
		slog.Error("failed to schedule disconnect", "peer_id", peerID, "error", err)
		respond.JsonError(w, "failed to disconnect peer", http.StatusInternalServerError)
		return
	}

	h.auditRepo.Log(r.Context(), &user.ID, "peer.disconnect",
		map[string]interface{}{"peer_id": peerID, "server_id": peer.ServerID}, r.RemoteAddr)

	respondDisconnect(w, outcome, "disconnect_pending")
}

func (h *Handler) ExportConfig(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	peerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	peer, err := h.peerRepo.GetByIDForPresharedKeyExport(r.Context(), peerID, user.ID, IsAdmin(user))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "peer not found", http.StatusNotFound)
		} else {
			respond.SafeError(w, "failed to load connection material", err, http.StatusInternalServerError)
		}
		return
	}

	if peer.UserID != user.ID && !IsAdmin(user) {
		respond.JsonError(w, "not your peer", http.StatusForbidden)
		return
	}
	if !peer.IsActive {
		respond.JsonError(w, "connection is inactive", http.StatusConflict)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err != nil {
		respond.JsonError(w, "server not found", http.StatusNotFound)
		return
	}

	ensureServerPublicKey(server)
	conf := h.buildWGConfig(peer, server)

	safeName := sanitizeDeviceName(peer.DeviceName)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="wg-%s.conf"`, safeName))
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

	peer, err := h.peerRepo.GetByIDForPresharedKeyExport(r.Context(), peerID, user.ID, IsAdmin(user))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "peer not found", http.StatusNotFound)
		} else {
			respond.SafeError(w, "failed to load connection material", err, http.StatusInternalServerError)
		}
		return
	}

	if peer.UserID != user.ID && !IsAdmin(user) {
		respond.JsonError(w, "not your peer", http.StatusForbidden)
		return
	}
	if !peer.IsActive {
		respond.JsonError(w, "connection is inactive", http.StatusConflict)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err != nil {
		respond.JsonError(w, "server not found", http.StatusNotFound)
		return
	}

	ensureServerPublicKey(server)
	conf := h.buildWGConfig(peer, server)

	png, err := qrcode.Encode(conf, qrcode.Medium, 512)
	if err != nil {
		slog.Error("qr generation error", "error", err)
		respond.JsonError(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="wg-%s.png"`, sanitizeDeviceName(peer.DeviceName)))
	w.WriteHeader(http.StatusOK)
	w.Write(png)
}

// ProxyCredentials issues one short-lived credential for one registered
// installation and one healthy, cluster-bound proxy gateway.
func (h *Handler) ProxyCredentials(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request struct {
		ServerID string        `json:"server_id"`
		Device   DeviceRequest `json:"device"`
	}
	if err := decodeStrictJSON(r.Body, &request); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	serverID, err := uuid.Parse(request.ServerID)
	if err != nil || serverID == uuid.Nil {
		respond.JsonError(w, "server_id must be a valid UUID", http.StatusBadRequest)
		return
	}
	deviceRequest, err := normalizeDeviceRequest(&request.Device, "")
	if err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	server, err := h.serverRepo.GetByID(r.Context(), serverID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "server not found", http.StatusNotFound)
		} else {
			respond.SafeError(w, "failed to load proxy server", err, http.StatusInternalServerError)
		}
		return
	}
	transport, ok := enabledServerTransport(server, "proxy")
	if !ok {
		respond.JsonError(w, "proxy transport is unavailable", http.StatusConflict)
		return
	}
	clusterID, err := h.multiclusterRepo.TransportCredentialCluster(r.Context(), serverID, "proxy", repo.DefaultNodeFreshness)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "proxy transport is not ready for cluster-scoped credentials", http.StatusConflict)
		} else {
			respond.SafeError(w, "failed to resolve proxy credential scope", err, http.StatusInternalServerError)
		}
		return
	}
	if h.transportTokenSigner == nil {
		respond.JsonError(w, "transport credential signer is unavailable", http.StatusServiceUnavailable)
		return
	}
	device, err := h.resolveRegisteredDevice(r.Context(), user.ID, deviceRequest)
	if errors.Is(err, repo.ErrDeviceRevoked) {
		respond.JsonErrorCode(w, "device is revoked", "device_revoked", http.StatusConflict)
		return
	}
	if err != nil {
		respond.SafeError(w, "failed to resolve device identity", err, http.StatusInternalServerError)
		return
	}
	proxyToken, err := h.transportTokenSigner.Issue(proxytoken.AudienceVPNProxy, user.ID, device.ID, serverID, clusterID, proxytoken.DefaultTTL)
	if err != nil {
		respond.SafeError(w, "failed to issue proxy credential", err, http.StatusInternalServerError)
		return
	}
	type proxyEndpoint struct {
		ServerID    uuid.UUID `json:"server_id"`
		Host        string    `json:"host"`
		Port        int       `json:"port"`
		CountryCode string    `json:"country_code"`
		Location    string    `json:"location"`
	}
	w.Header().Set("Cache-Control", "no-store")
	respond.JsonOK(w, map[string]interface{}{
		"proxy_token": proxyToken,
		"expires_in":  int(proxytoken.DefaultTTL.Seconds()),
		"device_id":   device.ID,
		"proxy_endpoint": proxyEndpoint{
			ServerID: server.ID, Host: transport.Host, Port: transport.Port,
			CountryCode: server.CountryCode, Location: server.Location,
		},
	}, http.StatusOK)
}

// TunnelCredentials issues a short-lived credential for an active device. It
// does not enable a transport by itself; clients must use a server-advertised capability.
func (h *Handler) TunnelCredentials(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	var req struct {
		PeerID string `json:"peer_id"`
	}
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	peerID, err := uuid.Parse(req.PeerID)
	if err != nil {
		respond.JsonError(w, "invalid peer_id", http.StatusBadRequest)
		return
	}
	peer, err := h.peerRepo.GetByID(r.Context(), peerID)
	if err != nil || peer.UserID != user.ID || !peer.IsActive || peer.DeviceID == nil {
		respond.JsonError(w, "active device not found", http.StatusNotFound)
		return
	}
	clusterID, err := h.multiclusterRepo.TransportCredentialCluster(r.Context(), peer.ServerID, "wss", repo.DefaultNodeFreshness)
	if errors.Is(err, pgx.ErrNoRows) {
		clusterID, err = h.multiclusterRepo.TransportCredentialCluster(r.Context(), peer.ServerID, "masque", repo.DefaultNodeFreshness)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "tunnel transport is not ready for cluster-scoped credentials", http.StatusConflict)
		} else {
			respond.SafeError(w, "failed to resolve tunnel credential scope", err, http.StatusInternalServerError)
		}
		return
	}
	if h.transportTokenSigner == nil {
		respond.JsonError(w, "transport credential signer is unavailable", http.StatusServiceUnavailable)
		return
	}
	token, err := h.transportTokenSigner.Issue(proxytoken.AudienceVPNTunnel, user.ID, *peer.DeviceID, peer.ServerID, clusterID, proxytoken.DefaultTTL)
	if err != nil {
		respond.SafeError(w, "failed to issue tunnel credential", err, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respond.JsonOK(w, map[string]interface{}{"tunnel_token": token, "expires_in": int(proxytoken.DefaultTTL.Seconds())}, http.StatusOK)
}

// ensureServerPublicKey fetches the real WireGuard public key from the core
// and updates the server record if it differs from what is stored.
func ensureServerPublicKey(server *models.VPNServer) {
	stats, err := CallCoreServerStats(server)
	if err != nil {
		slog.Warn("could not fetch core stats for public key", "server_id", server.ID, "error", err)
		return
	}
	if stats.PublicKey != "" && stats.PublicKey != server.PublicKey {
		slog.Info("updating server public key from core", "server_id", server.ID)
		server.PublicKey = stats.PublicKey
	}
}

func (h *Handler) buildWGConfig(peer *models.Peer, server *models.VPNServer) string {
	// Use Endpoint if set (public-facing host), otherwise fall back to Host
	epHost := server.Endpoint
	if epHost == "" {
		epHost = server.Host
	}
	endpoint := wireGuardEndpointForServerHost(epHost, server.WGPort)

	// Normalize AssignedIP: strip any duplicate /32 suffix from old DB rows,
	// then ensure exactly one /32 suffix is present.
	assignedIP := peer.AssignedIP
	for strings.HasSuffix(assignedIP, "/32/32") {
		assignedIP = strings.TrimSuffix(assignedIP, "/32")
	}
	if !strings.Contains(assignedIP, "/") {
		assignedIP += "/32"
	}

	return fmt.Sprintf(`[Interface]
PrivateKey = <YOUR_PRIVATE_KEY>
Address = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, assignedIP, h.vpnDNS, server.PublicKey, endpoint)
}

func (h *Handler) ListMyConnections(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	peers, err := h.peerRepo.ListActiveByUser(r.Context(), user.ID)
	if err != nil {
		slog.Error("list connections error", "error", err)
		respond.JsonError(w, "failed to list connections", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, peers, http.StatusOK)
}

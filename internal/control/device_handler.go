package control

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

type deviceResponse struct {
	ID               uuid.UUID                `json:"id"`
	ClientInstanceID *uuid.UUID               `json:"client_instance_id"`
	ReportedName     string                   `json:"reported_name"`
	Alias            string                   `json:"alias"`
	DisplayName      string                   `json:"display_name"`
	DeviceType       models.DeviceType        `json:"device_type"`
	AdapterReference string                   `json:"adapter_reference"`
	AdapterLabel     string                   `json:"adapter_label"`
	FirstSeenAt      time.Time                `json:"first_seen_at"`
	LastSeenAt       time.Time                `json:"last_seen_at"`
	RevokedAt        *time.Time               `json:"revoked_at"`
	Status           string                   `json:"status"`
	ActiveConnection *models.DeviceConnection `json:"active_connection"`
}

type deviceSessionPage struct {
	Items    []models.DeviceConnection `json:"items"`
	Page     int                       `json:"page"`
	PageSize int                       `json:"page_size"`
	Total    int                       `json:"total"`
}

type updateDeviceRequest struct {
	Alias string `json:"alias"`
}

func deviceConnectionFromPeer(peer *models.Peer) *models.DeviceConnection {
	if peer == nil || peer.DeviceID == nil {
		return nil
	}
	return &models.DeviceConnection{
		ID:            peer.ID,
		DeviceID:      *peer.DeviceID,
		ServerID:      peer.ServerID,
		Protocol:      "wireguard",
		PublicKey:     peer.PublicKey,
		AssignedIP:    peer.AssignedIP,
		IsActive:      peer.IsActive,
		BytesSent:     peer.BytesSent,
		BytesReceived: peer.BytesReceived,
		LastHandshake: peer.LastHandshake,
		CreatedAt:     peer.CreatedAt,
		ExpiresAt:     peer.ExpiresAt,
	}
}

func adapterLabel(reference string) string {
	if !adapterReferenceRe.MatchString(reference) {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(reference, "net-v1:"))
	if err != nil || len(raw) < 4 {
		return ""
	}
	return "LAN · " + strings.ToUpper(hex.EncodeToString(raw[:4]))
}

func presentDevice(device models.Device, active *models.Peer) deviceResponse {
	status := "disconnected"
	if device.RevokedAt != nil {
		status = "revoked"
	} else if active != nil {
		status = "connected"
	}
	return deviceResponse{
		ID:               device.ID,
		ClientInstanceID: device.ClientInstanceID,
		ReportedName:     device.ReportedName,
		Alias:            device.Alias,
		DisplayName:      device.DisplayName,
		DeviceType:       device.DeviceType,
		AdapterReference: device.AdapterReference,
		AdapterLabel:     adapterLabel(device.AdapterReference),
		FirstSeenAt:      device.FirstSeenAt,
		LastSeenAt:       device.LastSeenAt,
		RevokedAt:        device.RevokedAt,
		Status:           status,
		ActiveConnection: deviceConnectionFromPeer(active),
	}
}

func (h *Handler) ListMyDevices(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	devices, err := h.deviceRepo.ListByUser(r.Context(), user.ID)
	if err != nil {
		respond.SafeError(w, "failed to list devices", err, http.StatusInternalServerError)
		return
	}
	activePeers, err := h.peerRepo.ListActiveByUser(r.Context(), user.ID)
	if err != nil {
		respond.SafeError(w, "failed to list active device sessions", err, http.StatusInternalServerError)
		return
	}
	activeByDevice := make(map[uuid.UUID]*models.Peer, len(activePeers))
	for i := range activePeers {
		if activePeers[i].DeviceID != nil {
			activeByDevice[*activePeers[i].DeviceID] = &activePeers[i]
		}
	}
	response := make([]deviceResponse, 0, len(devices))
	for _, device := range devices {
		response = append(response, presentDevice(device, activeByDevice[device.ID]))
	}
	respond.JsonOK(w, response, http.StatusOK)
}

func (h *Handler) UpdateMyDevice(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	deviceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid device id", http.StatusBadRequest)
		return
	}
	var request updateDeviceRequest
	if err := decodeStrictJSON(r.Body, &request); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	request.Alias = strings.TrimSpace(request.Alias)
	if utf8.RuneCountInString(request.Alias) > 64 || strings.IndexFunc(request.Alias, unicode.IsControl) >= 0 {
		respond.JsonError(w, "alias must contain at most 64 visible characters", http.StatusBadRequest)
		return
	}
	device, err := h.deviceRepo.UpdateAlias(r.Context(), user.ID, deviceID, request.Alias)
	if errors.Is(err, pgx.ErrNoRows) {
		respond.JsonError(w, "device not found", http.StatusNotFound)
		return
	}
	if err != nil {
		respond.SafeError(w, "failed to update device", err, http.StatusInternalServerError)
		return
	}
	active, err := h.peerRepo.GetActiveByDevice(r.Context(), user.ID, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		active = nil
	} else if err != nil {
		respond.SafeError(w, "failed to load active device session", err, http.StatusInternalServerError)
		return
	}
	h.auditRepo.Log(r.Context(), &user.ID, "device.alias.update",
		map[string]interface{}{"device_id": deviceID, "has_alias": request.Alias != ""}, r.RemoteAddr)
	respond.JsonOK(w, presentDevice(*device, active), http.StatusOK)
}

func devicePagination(r *http.Request) (int, int) {
	page := 1
	pageSize := 20
	if value, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && value > 0 {
		page = value
	}
	if value, err := strconv.Atoi(r.URL.Query().Get("page_size")); err == nil && value >= 1 && value <= 100 {
		pageSize = value
	}
	return page, pageSize
}

func (h *Handler) ListMyDeviceSessions(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	deviceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid device id", http.StatusBadRequest)
		return
	}
	if _, err := h.deviceRepo.GetByUser(r.Context(), user.ID, deviceID); errors.Is(err, pgx.ErrNoRows) {
		respond.JsonError(w, "device not found", http.StatusNotFound)
		return
	} else if err != nil {
		respond.SafeError(w, "failed to load device", err, http.StatusInternalServerError)
		return
	}
	page, pageSize := devicePagination(r)
	total, err := h.peerRepo.CountByDevice(r.Context(), user.ID, deviceID)
	if err != nil {
		respond.SafeError(w, "failed to count device sessions", err, http.StatusInternalServerError)
		return
	}
	peers, err := h.peerRepo.ListByDevice(r.Context(), user.ID, deviceID, pageSize, (page-1)*pageSize)
	if err != nil {
		respond.SafeError(w, "failed to list device sessions", err, http.StatusInternalServerError)
		return
	}
	items := make([]models.DeviceConnection, 0, len(peers))
	for i := range peers {
		if session := deviceConnectionFromPeer(&peers[i]); session != nil {
			items = append(items, *session)
		}
	}
	respond.JsonOK(w, deviceSessionPage{Items: items, Page: page, PageSize: pageSize, Total: total}, http.StatusOK)
}

func (h *Handler) DeleteMyDevice(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	deviceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid device id", http.StatusBadRequest)
		return
	}
	device, err := h.deviceRepo.GetByUser(r.Context(), user.ID, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		respond.JsonError(w, "device not found", http.StatusNotFound)
		return
	}
	if err != nil {
		respond.SafeError(w, "failed to load device", err, http.StatusInternalServerError)
		return
	}
	if device.RevokedAt != nil {
		respond.JsonOK(w, presentDevice(*device, nil), http.StatusOK)
		return
	}

	active, err := h.peerRepo.GetActiveByDevice(r.Context(), user.ID, deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		active = nil
	} else if err != nil {
		respond.SafeError(w, "failed to load active device session", err, http.StatusInternalServerError)
		return
	}
	if active != nil {
		server, err := h.serverRepo.GetByID(r.Context(), active.ServerID)
		if err != nil {
			respond.SafeError(w, "failed to load device server", err, http.StatusInternalServerError)
			return
		}
		if err := CallCoreRemovePeer(server, active.PublicKey); err != nil {
			slog.Error("device cleanup did not converge", "device_id", deviceID, "peer_id", active.ID, "error", err)
			w.Header().Set("Retry-After", "5")
			respond.JsonErrorCode(w, "device cleanup did not converge; retry is required", "device_cleanup_pending", http.StatusServiceUnavailable)
			return
		}
	}

	revoked, err := h.deviceRepo.RevokeWithMaterial(r.Context(), user.ID, deviceID)
	if err != nil {
		respond.SafeError(w, "failed to revoke device material", err, http.StatusInternalServerError)
		return
	}
	if active != nil {
		h.detachPeerFromMeshSessions(r.Context(), active)
	}
	h.auditRepo.Log(r.Context(), &user.ID, "device.revoke",
		map[string]interface{}{"device_id": deviceID}, r.RemoteAddr)
	respond.JsonOK(w, presentDevice(*revoked, nil), http.StatusOK)
}

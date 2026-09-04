package control

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

// ═══════════════════════════════════════════════════════════════════════════
// User profile & Quota
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	quota, err := h.getUserQuota(r.Context(), user)
	if err != nil {
		respond.SafeError(w, "failed to load device quota", err, http.StatusInternalServerError)
		return
	}
	resp := map[string]any{
		"id":            user.ID,
		"authentik_uid": user.AuthentikUID,
		"email":         user.Email,
		"display_name":  user.DisplayName,
		"groups":        user.Groups,
		"is_banned":     user.IsBanned,
		"created_at":    user.CreatedAt,
		"updated_at":    user.UpdatedAt,
		"quota":         quota,
	}
	respond.JsonOK(w, resp, http.StatusOK)
}

func (h *Handler) GetQuota(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	quota, err := h.getUserQuota(r.Context(), user)
	if err != nil {
		respond.SafeError(w, "failed to load device quota", err, http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, quota, http.StatusOK)
}

func (h *Handler) DashboardSummary(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	quota, err := h.getUserQuota(r.Context(), user)
	if err != nil {
		respond.SafeError(w, "failed to load dashboard quota", err, http.StatusInternalServerError)
		return
	}
	snapshot, err := h.dashboardRepo.UserSnapshot(r.Context(), user.ID)
	if err != nil {
		respond.SafeError(w, "failed to load dashboard summary", err, http.StatusInternalServerError)
		return
	}

	availableDevices := quota.MaxDevices - snapshot.ConnectedDevices
	if availableDevices < 0 {
		availableDevices = 0
	}
	summary := models.DashboardSummary{
		RegisteredDevices: snapshot.RegisteredDevices,
		ConnectedDevices:  snapshot.ConnectedDevices,
		MaxDevices:        quota.MaxDevices,
		AvailableDevices:  availableDevices,
		PlanSlug:          quota.PlanSlug,
		PlanName:          quota.PlanName,
		Traffic:           snapshot.Traffic,
		RecentSessions:    snapshot.RecentSessions,
	}
	if IsAdmin(user) {
		infrastructure, err := h.dashboardRepo.Infrastructure(r.Context())
		if err != nil {
			respond.SafeError(w, "failed to load dashboard infrastructure", err, http.StatusInternalServerError)
			return
		}
		summary.Infrastructure = &infrastructure
	}

	respond.JsonOK(w, summary, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Servers (user-facing: list active only)
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) ListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListActive(r.Context())
	if err != nil {
		slog.Error("list servers error", "error", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}
	for index := range servers {
		usable := make([]models.TransportCapability, 0, len(servers[index].Transports))
		for _, transport := range servers[index].Transports {
			if transport.IsUsable() {
				usable = append(usable, transport)
			}
		}
		servers[index].SetTransports(usable)
		servers[index].ApplyCapabilities()
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
		slog.Error("ping servers list error", "error", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}

	respond.JsonOK(w, buildServerPingResults(servers), http.StatusOK)
}

func (h *Handler) AdminPingServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListAll(r.Context())
	if err != nil {
		slog.Error("admin ping servers list error", "error", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}

	respond.JsonOK(w, buildServerPingResults(servers), http.StatusOK)
}

func buildServerPingResults(servers []models.VPNServer) []ServerPingResult {
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

			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
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

	return results
}

// ═══════════════════════════════════════════════════════════════════════════
// User audit
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) MyAuditLogs(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	logs, err := h.auditRepo.ListByUser(r.Context(), user.ID, 50, 0)
	if err != nil {
		slog.Error("list audit logs error", "error", err)
		respond.JsonError(w, "failed to list audit logs", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, logs, http.StatusOK)
}

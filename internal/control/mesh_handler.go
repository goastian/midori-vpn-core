package control

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

const publicMeshNameFormat = "Servidor Comunitario %s [%s]"

// ipCountryMemCache is a process-level in-memory cache for IP→country lookups.
// Entries expire after 30 days; the cache is also persisted to/loaded from the
// ip_country_cache DB table so it survives container restarts.
var (
	ipCountryCacheMu  sync.RWMutex
	ipCountryMemCache = make(map[string]ipCacheEntry)
)

type ipCacheEntry struct {
	code    string
	expires time.Time
}

type MeshHandler struct {
	meshRepo  *repo.MeshRepo
	peerRepo  *repo.PeerRepo
	auditRepo *repo.AuditRepo
	wgMgr     *wg.Manager
	hub       *WSHub
	pool      *pgxpool.Pool

	// autoMeshLocks serializes ensureAutoMesh per user so concurrent
	// activate calls (e.g. agent restart racing with OAuth callback)
	// cannot create duplicate session meshes.
	autoMeshLocks sync.Map // map[uuid.UUID]*sync.Mutex
}

func NewMeshHandler(pool *pgxpool.Pool, wgMgr *wg.Manager, hub *WSHub) *MeshHandler {
	return &MeshHandler{
		meshRepo:  repo.NewMeshRepo(pool),
		peerRepo:  repo.NewPeerRepo(pool),
		auditRepo: repo.NewAuditRepo(pool),
		wgMgr:     wgMgr,
		hub:       hub,
		pool:      pool,
	}
}

// meshEvent is sent over WebSocket to notify members of changes.
type meshEvent struct {
	Type   string      `json:"type"`
	MeshID string      `json:"mesh_id"`
	Data   interface{} `json:"data,omitempty"`
}

type publicMeshNetwork struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Subnet      string    `json:"subnet"`
	MaxMembers  int       `json:"max_members"`
	IsActive    bool      `json:"is_active"`
	MemberCount int       `json:"member_count"`
	CountryCode string    `json:"country_code,omitempty"`
	PublicIP    string    `json:"public_ip,omitempty"`
	IsSession   bool      `json:"is_session"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func toPublicMeshNetwork(mesh models.MeshNetwork) publicMeshNetwork {
	return publicMeshNetwork{
		ID:          mesh.ID,
		Name:        mesh.Name,
		Description: mesh.Description,
		Subnet:      mesh.Subnet,
		MaxMembers:  mesh.MaxMembers,
		IsActive:    mesh.IsActive,
		MemberCount: mesh.MemberCount,
		CountryCode: mesh.CountryCode,
		PublicIP:    mesh.PublicIP,
		IsSession:   mesh.IsSession,
		CreatedAt:   mesh.CreatedAt,
		UpdatedAt:   mesh.UpdatedAt,
	}
}

func (h *MeshHandler) broadcastMeshListChanged() {
	if h.hub == nil {
		return
	}
	h.hub.Broadcast(meshEvent{Type: "mesh.list_changed"})
}

// memberUserIDs returns all member user IDs for a mesh as strings (for WS targeting).
func (h *MeshHandler) memberUserIDs(ctx context.Context, meshID uuid.UUID) []string {
	members, err := h.meshRepo.ListMembers(ctx, meshID)
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(members))
	for _, m := range members {
		ids = append(ids, m.UserID.String())
	}
	return ids
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /mesh — manual mesh creation is no longer supported
// ═══════════════════════════════════════════════════════════════════════════

func (h *MeshHandler) CreateMesh(w http.ResponseWriter, r *http.Request) {
	respond.JsonError(w, "manual mesh creation is disabled", http.StatusGone)
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /mesh — list the public global mesh directory
// ═══════════════════════════════════════════════════════════════════════════

func (h *MeshHandler) ListMyMeshes(w http.ResponseWriter, r *http.Request) {
	meshes, err := h.meshRepo.ListPublicDirectory(r.Context())
	if err != nil {
		slog.Error("mesh: list error", "error", err)
		respond.JsonError(w, "failed to list mesh networks", http.StatusInternalServerError)
		return
	}
	if meshes == nil {
		meshes = []models.MeshNetwork{}
	}
	publicMeshes := make([]publicMeshNetwork, 0, len(meshes))
	for i := range meshes {
		publicMeshes = append(publicMeshes, toPublicMeshNetwork(meshes[i]))
	}

	respond.JsonOK(w, publicMeshes, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /mesh/{id} — get public metadata for a mesh network
// ═══════════════════════════════════════════════════════════════════════════

type meshDetailResponse struct {
	publicMeshNetwork
	Members []models.MeshMember `json:"members"`
}

func (h *MeshHandler) GetMesh(w http.ResponseWriter, r *http.Request) {
	meshID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid mesh id", http.StatusBadRequest)
		return
	}

	mesh, err := h.meshRepo.GetByID(r.Context(), meshID)
	if err != nil {
		respond.JsonError(w, "mesh not found", http.StatusNotFound)
		return
	}
	if !isValidPublicMesh(mesh) {
		respond.JsonError(w, "mesh not found", http.StatusNotFound)
		return
	}

	members, err := h.meshRepo.ListMembers(r.Context(), meshID)
	if err != nil {
		slog.Warn("GetMesh: failed to list members", "mesh_id", meshID, "error", err)
		members = []models.MeshMember{}
	}

	respond.JsonOK(w, meshDetailResponse{publicMeshNetwork: toPublicMeshNetwork(*mesh), Members: members}, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /mesh/join — manual mesh invites are no longer supported
// ═══════════════════════════════════════════════════════════════════════════

func (h *MeshHandler) JoinMesh(w http.ResponseWriter, r *http.Request) {
	respond.JsonError(w, "manual mesh invites are disabled", http.StatusGone)
}

// ═══════════════════════════════════════════════════════════════════════════
// DELETE /mesh/{id} — leave a mesh (or delete it if the caller is the owner)
// ═══════════════════════════════════════════════════════════════════════════

func (h *MeshHandler) LeaveMesh(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	meshID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid mesh id", http.StatusBadRequest)
		return
	}

	mesh, err := h.meshRepo.GetByID(r.Context(), meshID)
	if err != nil {
		respond.JsonError(w, "mesh not found", http.StatusNotFound)
		return
	}

	if mesh.OwnerID == user.ID {
		// Collect member IDs before deletion so we can notify them.
		var memberIDsForNotify []string
		if h.hub != nil {
			memberIDsForNotify = h.memberUserIDs(r.Context(), meshID)
		}

		// Remove mesh IPs from WireGuard for all members before deleting.
		if h.wgMgr != nil {
			if members, err := h.meshRepo.ListMembers(r.Context(), meshID); err == nil {
				for _, m := range members {
					if m.PeerID == nil {
						continue
					}
					if peer, err := h.peerRepo.GetByID(r.Context(), *m.PeerID); err == nil {
						if wgErr := h.wgMgr.RemoveMeshIP(peer.PublicKey); wgErr != nil {
							slog.Warn("mesh: could not remove mesh IP from WireGuard on delete",
								"peer_id", m.PeerID, "error", wgErr)
						}
					}
				}
			}
		}
		// Owner deletes the whole network (cascades to members).
		if err := h.meshRepo.Delete(r.Context(), meshID); err != nil {
			slog.Error("mesh: delete error", "mesh_id", meshID, "error", err)
			respond.JsonError(w, "failed to delete mesh", http.StatusInternalServerError)
			return
		}
		h.auditRepo.Log(r.Context(), &user.ID, "mesh.delete",
			map[string]interface{}{"mesh_id": meshID}, r.RemoteAddr)

		// Notify former members that the mesh is gone.
		if h.hub != nil && len(memberIDsForNotify) > 0 {
			h.hub.BroadcastToUsers(memberIDsForNotify, meshEvent{
				Type:   "mesh.deleted",
				MeshID: meshID.String(),
			})
		}

		respond.JsonOK(w, map[string]string{"deleted": meshID.String()}, http.StatusOK)
		return
	}

	// Non-owner: just leave.
	memberRecord, err := h.meshRepo.GetMember(r.Context(), meshID, user.ID)
	if err != nil {
		respond.JsonError(w, "not a member of this mesh", http.StatusNotFound)
		return
	}

	// Remove mesh IP from WireGuard before removing from DB.
	if h.wgMgr != nil && memberRecord.PeerID != nil {
		if peer, err := h.peerRepo.GetByID(r.Context(), *memberRecord.PeerID); err == nil {
			if wgErr := h.wgMgr.RemoveMeshIP(peer.PublicKey); wgErr != nil {
				slog.Warn("mesh: could not remove mesh IP from WireGuard on leave",
					"peer_id", memberRecord.PeerID, "error", wgErr)
			}
		}
	}

	if err := h.meshRepo.RemoveMember(r.Context(), meshID, user.ID); err != nil {
		slog.Error("mesh: remove member error", "error", err)
		respond.JsonError(w, "failed to leave mesh", http.StatusInternalServerError)
		return
	}

	h.auditRepo.Log(r.Context(), &user.ID, "mesh.leave",
		map[string]interface{}{"mesh_id": meshID}, r.RemoteAddr)

	// Notify remaining members that this user left.
	if h.hub != nil {
		recipients := h.memberUserIDs(r.Context(), meshID)
		h.hub.BroadcastToUsers(recipients, meshEvent{
			Type:   "mesh.member_left",
			MeshID: meshID.String(),
			Data:   map[string]string{"user_id": user.ID.String()},
		})
	}

	respond.JsonOK(w, map[string]string{"left": meshID.String()}, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Node activation — simplified single-toggle mesh UX
//
//   GET    /mesh/node          → NodeStatus   (current node state)
//   POST   /mesh/node          → ActivateNode (auto-provision + join)
//   DELETE /mesh/node          → DeactivateNode (leave/delete all meshes)
//
// Users never need to manually create or join a mesh; the server handles it.
// ═══════════════════════════════════════════════════════════════════════════

type meshNodeStatus struct {
	Active   bool    `json:"active"`
	MeshIP   string  `json:"mesh_ip,omitempty"`
	MeshID   string  `json:"mesh_id,omitempty"`
	PublicIP string  `json:"public_ip,omitempty"`
	Peers    []nodeP `json:"peers"`
}

type nodeP struct {
	MeshIP      string `json:"mesh_ip"`
	DisplayName string `json:"display_name,omitempty"`
}

// nodeStatusForUser builds the current node status for a user without hitting HTTP.
func (h *MeshHandler) nodeStatusForUser(ctx context.Context, userID uuid.UUID) meshNodeStatus {
	meshes, err := h.meshRepo.ListByUser(ctx, userID)
	if err != nil || len(meshes) == 0 {
		return meshNodeStatus{Active: false, Peers: []nodeP{}}
	}
	for _, m := range meshes {
		if !m.IsActive {
			continue
		}
		member, err := h.meshRepo.GetMember(ctx, m.ID, userID)
		if err != nil {
			continue
		}
		peers := []nodeP{}
		if all, err := h.meshRepo.ListMembers(ctx, m.ID); err == nil {
			for _, p := range all {
				if p.UserID == userID {
					continue
				}
				peers = append(peers, nodeP{MeshIP: p.MeshIP, DisplayName: p.DisplayName})
			}
		}
		return meshNodeStatus{Active: true, MeshIP: member.MeshIP, MeshID: m.ID.String(), PublicIP: m.PublicIP, Peers: peers}
	}
	return meshNodeStatus{Active: false, Peers: []nodeP{}}
}

// GET /mesh/node
func (h *MeshHandler) NodeStatus(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	respond.JsonOK(w, h.nodeStatusForUser(r.Context(), user.ID), http.StatusOK)
}

// POST /mesh/node — activate user as a mesh node (auto-provisions personal mesh if needed)
func (h *MeshHandler) ActivateNode(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	mesh, member, created, err := h.ensureAutoMesh(r.Context(), r, user)
	if err != nil {
		slog.Warn("mesh: activate node failed", "error", err)
		respond.JsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	h.attachMemberToActivePeer(r.Context(), user.ID, mesh.ID, member.MeshIP)

	h.auditRepo.Log(r.Context(), &user.ID, "mesh.node.activate",
		map[string]interface{}{"mesh_id": mesh.ID, "mesh_ip": member.MeshIP}, r.RemoteAddr)
	if created {
		h.broadcastMeshListChanged()
	}

	respond.JsonOK(w,
		meshNodeStatus{Active: true, MeshIP: member.MeshIP, MeshID: mesh.ID.String(), PublicIP: mesh.PublicIP, Peers: []nodeP{}},
		statusCreated(created),
	)
}

// ═══════════════════════════════════════════════════════════════════════════
// Session mesh (auto) — POST /mesh/auto  &  DELETE /mesh/auto
//
// The extension calls POST on login → gets (or creates) a session mesh named
// "Servidor Comunitario 🇩🇴 [CC]" where CC is the 2-letter country from the request IP.
// DELETE /mesh/auto is called on logout / browser close to purge the data.
// ═══════════════════════════════════════════════════════════════════════════

func isValidCountryCode(code string) bool {
	if len(code) != 2 {
		return false
	}
	for _, ch := range code {
		if ch < 'A' || ch > 'Z' {
			return false
		}
	}
	return code != "XX"
}

func meshNameForCountry(country string) string {
	return fmt.Sprintf(publicMeshNameFormat, countryFlag(country), country)
}

func isValidPublicMesh(mesh *models.MeshNetwork) bool {
	return mesh != nil &&
		mesh.IsSession &&
		mesh.IsActive &&
		isValidCountryCode(mesh.CountryCode)
}

func countryFlag(country string) string {
	country = strings.ToUpper(country)
	if !isValidCountryCode(country) {
		return "🏳️"
	}
	runes := []rune(country)
	return string([]rune{0x1F1E6 + (runes[0] - 'A'), 0x1F1E6 + (runes[1] - 'A')})
}

func statusCreated(created bool) int {
	if created {
		return http.StatusCreated
	}
	return http.StatusOK
}

// countryFromIP resolves a 2-letter ISO country code from a public remote IP.
// Lookup order: in-memory cache → DB cache → ipapi.co API.
// Successful lookups are stored in both the in-memory cache (30-day TTL) and
// the ip_country_cache DB table so they survive container restarts.
// Unknown/private origins are rejected so "[XX]" is never persisted.
func (h *MeshHandler) countryFromIP(ctx context.Context, ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
		return "", fmt.Errorf("could not determine public origin country")
	}

	// 1. In-memory cache
	ipCountryCacheMu.RLock()
	if entry, ok := ipCountryMemCache[ip]; ok && time.Now().Before(entry.expires) {
		ipCountryCacheMu.RUnlock()
		return entry.code, nil
	}
	ipCountryCacheMu.RUnlock()

	// 2. DB cache
	if h.pool != nil {
		var code string
		err := h.pool.QueryRow(ctx,
			`SELECT country_code FROM ip_country_cache WHERE ip = $1`, ip,
		).Scan(&code)
		if err == nil && isValidCountryCode(code) {
			// warm in-memory cache and return
			ipCountryCacheMu.Lock()
			ipCountryMemCache[ip] = ipCacheEntry{code: code, expires: time.Now().Add(30 * 24 * time.Hour)}
			ipCountryCacheMu.Unlock()
			return code, nil
		}
	}

	// 3. Remote geo-IP API (ipapi.co)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://ipapi.co/%s/country/", ip))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("could not determine public origin country")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8))
	if err != nil {
		return "", fmt.Errorf("could not determine public origin country")
	}
	code := strings.ToUpper(strings.TrimSpace(string(body)))
	if !isValidCountryCode(code) {
		return "", fmt.Errorf("could not determine public origin country")
	}

	// Persist to in-memory cache
	ipCountryCacheMu.Lock()
	ipCountryMemCache[ip] = ipCacheEntry{code: code, expires: time.Now().Add(30 * 24 * time.Hour)}
	ipCountryCacheMu.Unlock()

	// Persist to DB (best-effort, non-blocking)
	if h.pool != nil {
		go func() {
			_, dbErr := h.pool.Exec(context.Background(),
				`INSERT INTO ip_country_cache (ip, country_code, cached_at)
				 VALUES ($1, $2, NOW())
				 ON CONFLICT (ip) DO UPDATE SET country_code = EXCLUDED.country_code, cached_at = NOW()`,
				ip, code,
			)
			if dbErr != nil {
				slog.Warn("ip_country_cache: failed to persist", "ip", ip, "error", dbErr)
			}
		}()
	}

	return code, nil
}

// realIP extracts the client IP from X-Forwarded-For or RemoteAddr.
func realIP(r *http.Request) string {
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		return cf
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		return r.RemoteAddr
	}
	return ip
}

func (h *MeshHandler) ensureAutoMesh(ctx context.Context, r *http.Request, u *models.User) (*models.MeshNetwork, *models.MeshMember, bool, error) {
	// Serialize per user so concurrent activate calls cannot both miss the
	// existing session mesh and race to create duplicates.
	lockIface, _ := h.autoMeshLocks.LoadOrStore(u.ID, &sync.Mutex{})
	lock := lockIface.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	originIP := realIP(r)
	meshes, err := h.meshRepo.ListByUser(ctx, u.ID)
	if err == nil {
		for i := range meshes {
			if !meshes[i].IsSession || meshes[i].OwnerID != u.ID {
				continue
			}
			if !isValidPublicMesh(&meshes[i]) {
				_ = h.meshRepo.Delete(ctx, meshes[i].ID)
				continue
			}
			member, err := h.meshRepo.GetMember(ctx, meshes[i].ID, u.ID)
			if err != nil {
				member = &models.MeshMember{UserID: u.ID}
				if err := h.meshRepo.AddMember(ctx, meshes[i].ID, member); err != nil {
					return nil, nil, false, fmt.Errorf("failed to initialize mesh")
				}
			}
			_ = h.meshRepo.TouchSession(ctx, meshes[i].ID)
			if originIP != "" && meshes[i].PublicIP != originIP {
				if country, err := h.countryFromIP(ctx, originIP); err == nil {
					meshes[i].CountryCode = country
					meshes[i].Name = meshNameForCountry(country)
					meshes[i].PublicIP = originIP
					_ = h.meshRepo.UpdateSessionOrigin(ctx, meshes[i].ID, meshes[i].Name, country, originIP)
				}
			}
			return &meshes[i], member, false, nil
		}
	}

	country, err := h.countryFromIP(ctx, originIP)
	if err != nil {
		return nil, nil, false, err
	}

	subnet, err := h.meshRepo.NextAvailableSubnet(ctx)
	if err != nil {
		slog.Error("auto-mesh: no available subnet", "error", err)
		return nil, nil, false, fmt.Errorf("no mesh subnets available")
	}

	mesh := &models.MeshNetwork{
		Name:        meshNameForCountry(country),
		OwnerID:     u.ID,
		Subnet:      subnet,
		MaxMembers:  50,
		IsSession:   true,
		CountryCode: country,
		PublicIP:    originIP,
	}
	if err := h.meshRepo.CreateSession(ctx, mesh); err != nil {
		slog.Error("auto-mesh: create error", "error", err)
		return nil, nil, false, fmt.Errorf("failed to create session mesh")
	}

	member := &models.MeshMember{UserID: u.ID}
	if err := h.meshRepo.AddMember(ctx, mesh.ID, member); err != nil {
		slog.Error("auto-mesh: add member — rolling back", "error", err)
		_ = h.meshRepo.Delete(ctx, mesh.ID)
		return nil, nil, false, fmt.Errorf("failed to initialize mesh")
	}
	return mesh, member, true, nil
}

func (h *MeshHandler) attachMemberToActivePeer(ctx context.Context, userID, meshID uuid.UUID, meshIP string) {
	peers, err := h.peerRepo.ListByUser(ctx, userID)
	if err != nil {
		return
	}
	for i := range peers {
		if !peers[i].IsActive {
			continue
		}
		peerID := peers[i].ID
		if h.wgMgr != nil {
			if wgErr := h.wgMgr.AddMeshIP(peers[i].PublicKey, meshIP); wgErr != nil {
				// This peer is marked active in the DB but not present in WireGuard
				// (e.g. the WG peer was removed while the DB record was not yet cleaned up).
				// Skip and try the next active peer.
				slog.Warn("mesh: could not add mesh IP to WireGuard", "peer_id", peerID, "error", wgErr)
				continue
			}
		}
		_ = h.meshRepo.UpdateMemberPeer(ctx, meshID, userID, &peerID)
		return
	}
}

// POST /mesh/auto — create or return the user's session mesh
func (h *MeshHandler) AutoMesh(w http.ResponseWriter, r *http.Request) {
	u := auth.GetUser(r)

	mesh, member, created, err := h.ensureAutoMesh(r.Context(), r, u)
	if err != nil {
		slog.Warn("auto-mesh: could not provision", "error", err)
		respond.JsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	h.attachMemberToActivePeer(r.Context(), u.ID, mesh.ID, member.MeshIP)

	h.auditRepo.Log(r.Context(), &u.ID, "mesh.auto.create",
		map[string]interface{}{"mesh_id": mesh.ID, "country": mesh.CountryCode}, r.RemoteAddr)
	if created {
		h.broadcastMeshListChanged()
	}

	respond.JsonOK(w, mesh, statusCreated(created))
}

// DELETE /mesh/auto — delete all session meshes for this user (logout/close)
func (h *MeshHandler) DeleteAutoMesh(w http.ResponseWriter, r *http.Request) {
	u := auth.GetUser(r)

	meshes, err := h.meshRepo.ListByUser(r.Context(), u.ID)
	if err != nil {
		respond.JsonError(w, "failed to list meshes", http.StatusInternalServerError)
		return
	}

	deleted := 0
	for _, m := range meshes {
		if !m.IsSession || m.OwnerID != u.ID {
			continue
		}
		// Clean up WireGuard routes for all members.
		if h.wgMgr != nil {
			if members, err := h.meshRepo.ListMembers(r.Context(), m.ID); err == nil {
				for _, mem := range members {
					if mem.PeerID == nil {
						continue
					}
					if peer, err := h.peerRepo.GetByID(r.Context(), *mem.PeerID); err == nil {
						_ = h.wgMgr.RemoveMeshIP(peer.PublicKey)
					}
				}
			}
		}
		if err := h.meshRepo.Delete(r.Context(), m.ID); err == nil {
			deleted++
		}
	}

	h.auditRepo.Log(r.Context(), &u.ID, "mesh.auto.delete",
		map[string]interface{}{"deleted": deleted}, r.RemoteAddr)
	if deleted > 0 {
		h.broadcastMeshListChanged()
	}

	respond.JsonOK(w, map[string]int{"deleted": deleted}, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /mesh/{id}/invite — manual mesh invites are no longer supported
// ═══════════════════════════════════════════════════════════════════════════

func (h *MeshHandler) RegenerateInvite(w http.ResponseWriter, r *http.Request) {
	respond.JsonError(w, "manual mesh invites are disabled", http.StatusGone)
}

// DELETE /mesh/node — deactivate; leaves or deletes every mesh the user belongs to
func (h *MeshHandler) DeactivateNode(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	meshes, err := h.meshRepo.ListByUser(r.Context(), user.ID)
	if err != nil {
		respond.JsonError(w, "failed to list meshes", http.StatusInternalServerError)
		return
	}

	for _, m := range meshes {
		memberRecord, err := h.meshRepo.GetMember(r.Context(), m.ID, user.ID)
		if err != nil {
			continue
		}
		// Remove WireGuard routing first.
		if h.wgMgr != nil && memberRecord.PeerID != nil {
			if peer, err := h.peerRepo.GetByID(r.Context(), *memberRecord.PeerID); err == nil {
				_ = h.wgMgr.RemoveMeshIP(peer.PublicKey)
			}
		}
		if m.OwnerID == user.ID {
			_ = h.meshRepo.Delete(r.Context(), m.ID)
		} else {
			_ = h.meshRepo.RemoveMember(r.Context(), m.ID, user.ID)
		}
	}

	h.auditRepo.Log(r.Context(), &user.ID, "mesh.node.deactivate", nil, r.RemoteAddr)
	h.broadcastMeshListChanged()
	respond.JsonOK(w, meshNodeStatus{Active: false, Peers: []nodeP{}}, http.StatusOK)
}

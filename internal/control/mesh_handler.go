package control

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
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

// meshNameMaxLen is the maximum allowed byte length for a mesh network name.
const meshNameMaxLen = 64

// maxMeshesPerUser caps how many mesh networks a single user may own.
const maxMeshesPerUser = 10

type MeshHandler struct {
	meshRepo  *repo.MeshRepo
	peerRepo  *repo.PeerRepo
	auditRepo *repo.AuditRepo
	wgMgr     *wg.Manager
	hub       *WSHub
}

func NewMeshHandler(pool *pgxpool.Pool, wgMgr *wg.Manager, hub *WSHub) *MeshHandler {
	return &MeshHandler{
		meshRepo:  repo.NewMeshRepo(pool),
		peerRepo:  repo.NewPeerRepo(pool),
		auditRepo: repo.NewAuditRepo(pool),
		wgMgr:     wgMgr,
		hub:       hub,
	}
}

// meshEvent is sent over WebSocket to notify members of changes.
type meshEvent struct {
	Type   string      `json:"type"`
	MeshID string      `json:"mesh_id"`
	Data   interface{} `json:"data,omitempty"`
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

// sanitizeMeshName removes dangerous characters and truncates to meshNameMaxLen.
func sanitizeMeshName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > meshNameMaxLen {
		s = s[:meshNameMaxLen]
	}
	return s
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /mesh — create a new mesh network
// ═══════════════════════════════════════════════════════════════════════════

type createMeshRequest struct {
	Name               string `json:"name"`
	Description        string `json:"description"`
	MaxMembers         int    `json:"max_members"`
	InviteExpiresInDays int   `json:"invite_expires_in_days"`
}

func (h *MeshHandler) CreateMesh(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	var req createMeshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	req.Name = sanitizeMeshName(req.Name)
	if req.Name == "" {
		respond.JsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.MaxMembers <= 0 || req.MaxMembers > 250 {
		req.MaxMembers = 10
	}

	// Enforce per-user mesh creation limit.
	owned, err := h.meshRepo.CountByOwner(r.Context(), user.ID)
	if err != nil {
		slog.Error("mesh: count owned meshes", "error", err)
		respond.JsonError(w, "failed to check mesh quota", http.StatusInternalServerError)
		return
	}
	if owned >= maxMeshesPerUser {
		respond.JsonError(w, "mesh network limit reached", http.StatusConflict)
		return
	}

	subnet, err := h.meshRepo.NextAvailableSubnet(r.Context())
	if err != nil {
		slog.Error("mesh: no available subnet", "error", err)
		respond.JsonError(w, "no mesh subnets available", http.StatusServiceUnavailable)
		return
	}

	mesh := &models.MeshNetwork{
		Name:        req.Name,
		Description: strings.TrimSpace(req.Description),
		OwnerID:     user.ID,
		Subnet:      subnet,
		MaxMembers:  req.MaxMembers,
	}
	if req.InviteExpiresInDays > 0 {
		exp := time.Now().UTC().AddDate(0, 0, req.InviteExpiresInDays)
		mesh.InviteExpiresAt = &exp
	}

	if err := h.meshRepo.Create(r.Context(), mesh); err != nil {
		slog.Error("mesh: create error", "error", err)
		respond.JsonError(w, "failed to create mesh network", http.StatusInternalServerError)
		return
	}

	// Owner automatically becomes the first member with IP .1 reserved for
	// the gateway; the owner receives .2.
	member := &models.MeshMember{UserID: user.ID}
	if err := h.meshRepo.AddMember(r.Context(), mesh.ID, member); err != nil {
		slog.Error("mesh: add owner as member — rolling back mesh creation", "error", err)
		if delErr := h.meshRepo.Delete(r.Context(), mesh.ID); delErr != nil {
			slog.Error("mesh: rollback delete failed", "mesh_id", mesh.ID, "error", delErr)
		}
		respond.JsonError(w, "failed to initialize mesh membership", http.StatusInternalServerError)
		return
	}

	h.auditRepo.Log(r.Context(), &user.ID, "mesh.create",
		map[string]interface{}{"mesh_id": mesh.ID, "name": mesh.Name}, r.RemoteAddr)

	respond.JsonOK(w, mesh, http.StatusCreated)
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /mesh — list all mesh networks the current user belongs to (or owns)
// ═══════════════════════════════════════════════════════════════════════════

func (h *MeshHandler) ListMyMeshes(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	meshes, err := h.meshRepo.ListByUser(r.Context(), user.ID)
	if err != nil {
		slog.Error("mesh: list error", "error", err)
		respond.JsonError(w, "failed to list mesh networks", http.StatusInternalServerError)
		return
	}
	if meshes == nil {
		meshes = []models.MeshNetwork{}
	}

	// Hide invite_code for meshes the user does not own.
	for i := range meshes {
		if meshes[i].OwnerID != user.ID {
			meshes[i].InviteCode = ""
		}
	}

	respond.JsonOK(w, meshes, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// GET /mesh/{id} — get a mesh network with its members (must be a member)
// ═══════════════════════════════════════════════════════════════════════════

type meshDetailResponse struct {
	models.MeshNetwork
	Members []models.MeshMember `json:"members"`
}

func (h *MeshHandler) GetMesh(w http.ResponseWriter, r *http.Request) {
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

	// Verify the caller is a member (or owner).
	if _, err := h.meshRepo.GetMember(r.Context(), meshID, user.ID); err != nil {
		if mesh.OwnerID != user.ID {
			respond.JsonError(w, "not a member of this mesh", http.StatusForbidden)
			return
		}
	}

	// Only expose invite_code to the owner.
	if mesh.OwnerID != user.ID {
		mesh.InviteCode = ""
	}

	members, err := h.meshRepo.ListMembers(r.Context(), meshID)
	if err != nil {
		slog.Error("mesh: list members error", "mesh_id", meshID, "error", err)
		respond.JsonError(w, "failed to list members", http.StatusInternalServerError)
		return
	}
	if members == nil {
		members = []models.MeshMember{}
	}

	respond.JsonOK(w, meshDetailResponse{MeshNetwork: *mesh, Members: members}, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /mesh/join — join a mesh network using an invite code
// ═══════════════════════════════════════════════════════════════════════════

type joinMeshRequest struct {
	InviteCode string `json:"invite_code"`
}

func (h *MeshHandler) JoinMesh(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	var req joinMeshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	req.InviteCode = strings.TrimSpace(req.InviteCode)
	if req.InviteCode == "" {
		respond.JsonError(w, "invite_code is required", http.StatusBadRequest)
		return
	}

	mesh, err := h.meshRepo.GetByInviteCode(r.Context(), req.InviteCode)
	if err != nil {
		respond.JsonError(w, "invalid invite code", http.StatusNotFound)
		return
	}
	if !mesh.IsActive {
		respond.JsonError(w, "mesh network is inactive", http.StatusGone)
		return
	}

	// Check already a member.
	if _, err := h.meshRepo.GetMember(r.Context(), mesh.ID, user.ID); err == nil {
		respond.JsonError(w, "already a member of this mesh", http.StatusConflict)
		return
	}

	// Enforce max_members.
	count, err := h.meshRepo.CountMembers(r.Context(), mesh.ID)
	if err != nil {
		slog.Error("mesh: count members error", "error", err)
		respond.JsonError(w, "failed to check member count", http.StatusInternalServerError)
		return
	}
	if count >= mesh.MaxMembers {
		respond.JsonError(w, "mesh network is full", http.StatusConflict)
		return
	}

	// Attach to the user's most recent active peer if available.
	var peerID *uuid.UUID
	peers, err := h.peerRepo.ListByUser(r.Context(), user.ID)
	if err == nil {
		for i := range peers {
			if peers[i].IsActive {
				id := peers[i].ID
				peerID = &id
				break
			}
		}
	}

	member := &models.MeshMember{UserID: user.ID, PeerID: peerID}
	if err := h.meshRepo.AddMember(r.Context(), mesh.ID, member); err != nil {
		slog.Error("mesh: add member error", "error", err)
		respond.JsonError(w, "failed to join mesh", http.StatusInternalServerError)
		return
	}

	// Push mesh IP to WireGuard AllowedIPs so packets to 10.200.x.x actually route.
	if peerID != nil && h.wgMgr != nil {
		if peer, err := h.peerRepo.GetByID(r.Context(), *peerID); err == nil {
			if wgErr := h.wgMgr.AddMeshIP(peer.PublicKey, member.MeshIP); wgErr != nil {
				// Non-fatal: DB membership succeeded; log and continue.
				slog.Warn("mesh: could not add mesh IP to WireGuard",
					"peer_id", peerID, "mesh_ip", member.MeshIP, "error", wgErr)
			}
		}
	}

	h.auditRepo.Log(r.Context(), &user.ID, "mesh.join",
		map[string]interface{}{"mesh_id": mesh.ID, "mesh_ip": member.MeshIP}, r.RemoteAddr)

	// Notify all mesh members (including the new joiner) via WebSocket.
	if h.hub != nil {
		recipients := h.memberUserIDs(r.Context(), mesh.ID)
		h.hub.BroadcastToUsers(recipients, meshEvent{
			Type:   "mesh.member_joined",
			MeshID: mesh.ID.String(),
			Data:   map[string]string{"user_id": user.ID.String(), "mesh_ip": member.MeshIP},
		})
	}

	respond.JsonOK(w, member, http.StatusCreated)
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
	Active bool    `json:"active"`
	MeshIP string  `json:"mesh_ip,omitempty"`
	MeshID string  `json:"mesh_id,omitempty"`
	Peers  []nodeP `json:"peers"`
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
		return meshNodeStatus{Active: true, MeshIP: member.MeshIP, MeshID: m.ID.String(), Peers: peers}
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

	// Already active — return current status.
	if status := h.nodeStatusForUser(r.Context(), user.ID); status.Active {
		respond.JsonOK(w, status, http.StatusOK)
		return
	}

	// Enforce per-user mesh quota.
	owned, err := h.meshRepo.CountByOwner(r.Context(), user.ID)
	if err != nil {
		respond.JsonError(w, "failed to check mesh quota", http.StatusInternalServerError)
		return
	}
	if owned >= maxMeshesPerUser {
		respond.JsonError(w, "mesh network limit reached", http.StatusConflict)
		return
	}

	subnet, err := h.meshRepo.NextAvailableSubnet(r.Context())
	if err != nil {
		respond.JsonError(w, "no mesh subnets available", http.StatusServiceUnavailable)
		return
	}

	mesh := &models.MeshNetwork{
		Name:       "My Mesh",
		OwnerID:    user.ID,
		Subnet:     subnet,
		MaxMembers: 50,
	}
	if err := h.meshRepo.Create(r.Context(), mesh); err != nil {
		slog.Error("mesh: activate node create error", "error", err)
		respond.JsonError(w, "failed to provision mesh node", http.StatusInternalServerError)
		return
	}

	member := &models.MeshMember{UserID: user.ID}
	if err := h.meshRepo.AddMember(r.Context(), mesh.ID, member); err != nil {
		slog.Error("mesh: activate node add member — rolling back", "error", err)
		_ = h.meshRepo.Delete(r.Context(), mesh.ID)
		respond.JsonError(w, "failed to provision mesh node", http.StatusInternalServerError)
		return
	}

	// Route mesh IP through WireGuard.
	if h.wgMgr != nil {
		if peers, err := h.peerRepo.ListByUser(r.Context(), user.ID); err == nil {
			for i := range peers {
				if peers[i].IsActive {
					if wgErr := h.wgMgr.AddMeshIP(peers[i].PublicKey, member.MeshIP); wgErr != nil {
						slog.Warn("mesh: activate node WG routing error", "error", wgErr)
					}
					break
				}
			}
		}
	}

	h.auditRepo.Log(r.Context(), &user.ID, "mesh.node.activate",
		map[string]interface{}{"mesh_id": mesh.ID, "mesh_ip": member.MeshIP}, r.RemoteAddr)

	respond.JsonOK(w,
		meshNodeStatus{Active: true, MeshIP: member.MeshIP, MeshID: mesh.ID.String(), Peers: []nodeP{}},
		http.StatusCreated,
	)
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
	respond.JsonOK(w, meshNodeStatus{Active: false, Peers: []nodeP{}}, http.StatusOK)
}

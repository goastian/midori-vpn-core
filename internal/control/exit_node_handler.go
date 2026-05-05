package control

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

// ExitNodeHandler handles the exit-node sub-routes under /api/v1/control/mesh.
type ExitNodeHandler struct {
	repo     *repo.ExitNodeRepo
	meshRepo *repo.MeshRepo
}

func NewExitNodeHandler(pool *pgxpool.Pool) *ExitNodeHandler {
	return &ExitNodeHandler{
		repo:     repo.NewExitNodeRepo(pool),
		meshRepo: repo.NewMeshRepo(pool),
	}
}

// RegisterExitNode marks the calling user as an exit node in one of their mesh memberships.
// POST /api/v1/control/mesh/exit-node/register
// Body: { "mesh_id": "...", "proxy_port": 8888 }
func (h *ExitNodeHandler) RegisterExitNode(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userID := user.ID

	var req struct {
		MeshID    uuid.UUID `json:"mesh_id"`
		ProxyPort int       `json:"proxy_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ProxyPort <= 0 || req.ProxyPort > 65535 {
		respond.JsonError(w, "proxy_port must be 1-65535", http.StatusBadRequest)
		return
	}
	if req.MeshID == uuid.Nil {
		respond.JsonError(w, "mesh_id required", http.StatusBadRequest)
		return
	}

	if err := h.repo.RegisterExitNode(r.Context(), userID, req.MeshID, req.ProxyPort); err != nil {
		slog.Error("RegisterExitNode", "err", err)
		respond.JsonError(w, "failed to register exit node", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, map[string]string{"status": "registered"}, http.StatusOK)
}

// DeregisterExitNode removes the calling user's exit-node status.
// DELETE /api/v1/control/mesh/exit-node/register
// Body: { "mesh_id": "..." }
func (h *ExitNodeHandler) DeregisterExitNode(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userID := user.ID

	var req struct {
		MeshID uuid.UUID `json:"mesh_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.MeshID == uuid.Nil {
		respond.JsonError(w, "mesh_id required", http.StatusBadRequest)
		return
	}

	if err := h.repo.DeregisterExitNode(r.Context(), userID, req.MeshID); err != nil {
		slog.Error("DeregisterExitNode", "err", err)
		respond.JsonError(w, "failed to deregister exit node", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, map[string]string{"status": "deregistered"}, http.StatusOK)
}

// ListExitNodes returns all exit nodes visible to the calling user.
// GET /api/v1/control/mesh/exit-nodes
func (h *ExitNodeHandler) ListExitNodes(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userID := user.ID

	nodes, err := h.repo.ListExitNodes(r.Context(), userID)
	if err != nil {
		slog.Error("ListExitNodes", "err", err)
		respond.JsonError(w, "failed to list exit nodes", http.StatusInternalServerError)
		return
	}
	if nodes == nil {
		nodes = []repo.ExitNode{}
	}
	respond.JsonOK(w, nodes, http.StatusOK)
}

// SetExitNode selects an exit node for the calling user.
// PUT /api/v1/control/mesh/exit-node
// Body: { "user_id": "...", "mesh_ip": "10.200.x.y", "proxy_port": 8888 }
func (h *ExitNodeHandler) SetExitNode(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	callerID := user.ID

	var req struct {
		UserID    uuid.UUID `json:"user_id"`
		MeshIP    string    `json:"mesh_ip"`
		ProxyPort int       `json:"proxy_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.MeshIP == "" || req.ProxyPort <= 0 {
		respond.JsonError(w, "mesh_ip and proxy_port required", http.StatusBadRequest)
		return
	}

	if err := h.repo.SetUserExitNode(r.Context(), callerID, req.MeshIP, req.ProxyPort); err != nil {
		slog.Error("SetExitNode", "err", err)
		respond.JsonError(w, "failed to set exit node", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// ClearExitNode removes the caller's exit-node selection.
// DELETE /api/v1/control/mesh/exit-node
func (h *ExitNodeHandler) ClearExitNode(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	callerID := user.ID

	if err := h.repo.ClearUserExitNode(r.Context(), callerID); err != nil && err != pgx.ErrNoRows {
		slog.Error("ClearExitNode", "err", err)
		respond.JsonError(w, "failed to clear exit node", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, map[string]string{"status": "cleared"}, http.StatusOK)
}

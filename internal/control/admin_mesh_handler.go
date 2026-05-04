package control

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

// AdminMeshHandler serves admin-only mesh overview endpoints.
type AdminMeshHandler struct {
	meshRepo *repo.MeshRepo
}

func NewAdminMeshHandler(pool *pgxpool.Pool) *AdminMeshHandler {
	return &AdminMeshHandler{meshRepo: repo.NewMeshRepo(pool)}
}

// adminMeshNetwork is the response shape for the admin mesh list endpoint.
type adminMeshNetwork struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Subnet      string                 `json:"subnet"`
	IsActive    bool                   `json:"is_active"`
	MemberCount int                    `json:"member_count"`
	CountryCode string                 `json:"country_code"`
	PublicIP    string                 `json:"public_ip,omitempty"`
	IsSession   bool                   `json:"is_session"`
	CreatedAt   time.Time              `json:"created_at"`
	Members     []repo.AdminMeshMember `json:"members"`
}

// GET /api/v1/admin/mesh
// Returns all mesh networks with their members and per-member connection status.
func (h *AdminMeshHandler) AdminListMeshes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	meshes, err := h.meshRepo.ListAll(ctx)
	if err != nil {
		respond.JsonError(w, "failed to list mesh networks", http.StatusInternalServerError)
		return
	}

	// Fetch members for every mesh concurrently.
	result := make([]adminMeshNetwork, len(meshes))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, m := range meshes {
		wg.Add(1)
		go func(idx int, meshID uuid.UUID, meshName string) {
			defer wg.Done()
			members, err := h.meshRepo.ListMembersAdmin(ctx, meshID)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				slog.Warn("admin mesh: failed to load members", "mesh_id", meshID, "mesh", meshName, "error", err)
				result[idx].Members = []repo.AdminMeshMember{}
				return
			}
			if members == nil {
				members = []repo.AdminMeshMember{}
			}
			result[idx].Members = members
		}(i, m.ID, m.Name)

		result[i] = adminMeshNetwork{
			ID:          m.ID.String(),
			Name:        m.Name,
			Subnet:      m.Subnet,
			IsActive:    m.IsActive,
			MemberCount: m.MemberCount,
			CountryCode: m.CountryCode,
			PublicIP:    m.PublicIP,
			IsSession:   m.IsSession,
			CreatedAt:   m.CreatedAt,
		}
	}
	wg.Wait()

	respond.JsonOK(w, result, http.StatusOK)
}

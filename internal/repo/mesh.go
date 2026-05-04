package repo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

// meshSubnetBase is the base of the range used for auto-allocated mesh subnets.
// Each mesh network gets a /24 from 10.200.1.0 – 10.200.254.0.
const meshSubnetBase = "10.200"

type MeshRepo struct {
	pool *pgxpool.Pool
}

func NewMeshRepo(pool *pgxpool.Pool) *MeshRepo {
	return &MeshRepo{pool: pool}
}

// generateInviteCode returns a random 16-byte hex string suitable for invite codes.
func generateInviteCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NextAvailableSubnet picks the first unused /24 in the 10.200.x.0/24 range.
func (r *MeshRepo) NextAvailableSubnet(ctx context.Context) (string, error) {
	rows, err := r.pool.Query(ctx, `SELECT subnet FROM mesh_networks`)
	if err != nil {
		return "", fmt.Errorf("mesh: list subnets: %w", err)
	}
	defer rows.Close()

	used := make(map[string]bool)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return "", err
		}
		used[s] = true
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	for i := 1; i <= 254; i++ {
		candidate := fmt.Sprintf("%s.%d.0/24", meshSubnetBase, i)
		if !used[candidate] {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("mesh: no available /24 subnet in %s.0.0/16", meshSubnetBase)
}

// nextAvailableMeshIP returns the lowest host address (.2, .3 …) within
// subnet that is not already allocated to a mesh member.
func (r *MeshRepo) nextAvailableMeshIP(ctx context.Context, meshID uuid.UUID, subnet string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("mesh: parse subnet %q: %w", subnet, err)
	}

	rows, err := r.pool.Query(ctx,
		`SELECT mesh_ip FROM mesh_members WHERE mesh_id = $1`, meshID)
	if err != nil {
		return "", fmt.Errorf("mesh: list ips: %w", err)
	}
	defer rows.Close()

	used := make(map[string]bool)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return "", err
		}
		used[ip] = true
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	base := ipNet.IP.To4()
	if base == nil {
		return "", fmt.Errorf("mesh: only IPv4 subnets are supported")
	}

	// .1 is reserved as the gateway; start from .2
	for i := 2; i <= 254; i++ {
		candidate := fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], i)
		if !used[candidate] {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("mesh: subnet %s is full", subnet)
}

// Create inserts a new mesh network, auto-generating its invite code.
func (r *MeshRepo) Create(ctx context.Context, mesh *models.MeshNetwork) error {
	code, err := generateInviteCode()
	if err != nil {
		return fmt.Errorf("mesh: generate invite code: %w", err)
	}
	mesh.InviteCode = code

	query := `
		INSERT INTO mesh_networks (name, description, owner_id, subnet, invite_code, max_members, invite_expires_at, country_code, is_session)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, is_active, created_at, updated_at
	`
	return r.pool.QueryRow(ctx, query,
		mesh.Name, mesh.Description, mesh.OwnerID, mesh.Subnet, mesh.InviteCode,
		mesh.MaxMembers, mesh.InviteExpiresAt, mesh.CountryCode, mesh.IsSession,
	).Scan(&mesh.ID, &mesh.IsActive, &mesh.CreatedAt, &mesh.UpdatedAt)
}

// CreateSession is like Create but marks the mesh as a session mesh (is_session=true).
func (r *MeshRepo) CreateSession(ctx context.Context, mesh *models.MeshNetwork) error {
	mesh.IsSession = true
	return r.Create(ctx, mesh)
}

// GetByID returns a mesh network by its UUID, including member count.
// invite_code is always populated so callers can decide whether to expose it.
func (r *MeshRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.MeshNetwork, error) {
	query := `
		SELECT n.id, n.name, n.description, n.owner_id, n.subnet, n.invite_code,
		       n.invite_expires_at, n.max_members, n.is_active, n.created_at, n.updated_at,
		       COUNT(m.id) AS member_count, n.country_code, n.is_session
		FROM mesh_networks n
		LEFT JOIN mesh_members m ON m.mesh_id = n.id
		WHERE n.id = $1
		GROUP BY n.id
	`
	var mesh models.MeshNetwork
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&mesh.ID, &mesh.Name, &mesh.Description, &mesh.OwnerID, &mesh.Subnet, &mesh.InviteCode,
		&mesh.InviteExpiresAt, &mesh.MaxMembers, &mesh.IsActive, &mesh.CreatedAt, &mesh.UpdatedAt,
		&mesh.MemberCount, &mesh.CountryCode, &mesh.IsSession,
	)
	if err != nil {
		return nil, fmt.Errorf("mesh: get by id: %w", err)
	}
	return &mesh, nil
}

// GetByInviteCode looks up a mesh network using its invite code.
// Returns an error if the code is expired.
func (r *MeshRepo) GetByInviteCode(ctx context.Context, code string) (*models.MeshNetwork, error) {
	query := `
		SELECT n.id, n.name, n.description, n.owner_id, n.subnet, n.invite_code,
		       n.invite_expires_at, n.max_members, n.is_active, n.created_at, n.updated_at,
		       COUNT(m.id) AS member_count, n.country_code, n.is_session
		FROM mesh_networks n
		LEFT JOIN mesh_members m ON m.mesh_id = n.id
		WHERE n.invite_code = $1
		  AND (n.invite_expires_at IS NULL OR n.invite_expires_at > NOW())
		GROUP BY n.id
	`
	var mesh models.MeshNetwork
	err := r.pool.QueryRow(ctx, query, code).Scan(
		&mesh.ID, &mesh.Name, &mesh.Description, &mesh.OwnerID, &mesh.Subnet, &mesh.InviteCode,
		&mesh.InviteExpiresAt, &mesh.MaxMembers, &mesh.IsActive, &mesh.CreatedAt, &mesh.UpdatedAt,
		&mesh.MemberCount, &mesh.CountryCode, &mesh.IsSession,
	)
	if err != nil {
		return nil, fmt.Errorf("mesh: get by invite code: %w", err)
	}
	return &mesh, nil
}

// ListByUser returns all mesh networks where the given user is the owner or a member.
func (r *MeshRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.MeshNetwork, error) {
	query := `
		SELECT DISTINCT n.id, n.name, n.description, n.owner_id, n.subnet, n.invite_code,
		       n.invite_expires_at, n.max_members, n.is_active, n.created_at, n.updated_at,
		       COUNT(m2.id) AS member_count, n.country_code, n.is_session
		FROM mesh_networks n
		LEFT JOIN mesh_members m2 ON m2.mesh_id = n.id
		WHERE n.owner_id = $1
		   OR EXISTS (SELECT 1 FROM mesh_members mm WHERE mm.mesh_id = n.id AND mm.user_id = $1)
		GROUP BY n.id
		ORDER BY n.created_at DESC
	`
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("mesh: list by user: %w", err)
	}
	defer rows.Close()

	var meshes []models.MeshNetwork
	for rows.Next() {
		var mesh models.MeshNetwork
		if err := rows.Scan(
			&mesh.ID, &mesh.Name, &mesh.Description, &mesh.OwnerID, &mesh.Subnet, &mesh.InviteCode,
			&mesh.InviteExpiresAt, &mesh.MaxMembers, &mesh.IsActive, &mesh.CreatedAt, &mesh.UpdatedAt,
			&mesh.MemberCount, &mesh.CountryCode, &mesh.IsSession,
		); err != nil {
			return nil, err
		}
		meshes = append(meshes, mesh)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mesh: list by user rows: %w", err)
	}
	return meshes, nil
}

// Delete removes a mesh network (owner only, enforced at handler level).
func (r *MeshRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM mesh_networks WHERE id = $1`, id)
	return err
}

// GetMember returns a single membership record.
func (r *MeshRepo) GetMember(ctx context.Context, meshID, userID uuid.UUID) (*models.MeshMember, error) {
	query := `
		SELECT id, mesh_id, user_id, peer_id, mesh_ip, joined_at
		FROM mesh_members
		WHERE mesh_id = $1 AND user_id = $2
	`
	var m models.MeshMember
	err := r.pool.QueryRow(ctx, query, meshID, userID).Scan(
		&m.ID, &m.MeshID, &m.UserID, &m.PeerID, &m.MeshIP, &m.JoinedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("mesh: get member: %w", err)
	}
	return &m, nil
}

// AddMember inserts a new member into a mesh, auto-assigning a mesh IP.
// The member's PeerID may be nil if the user has no active VPN peer yet.
func (r *MeshRepo) AddMember(ctx context.Context, meshID uuid.UUID, member *models.MeshMember) error {
	mesh, err := r.GetByID(ctx, meshID)
	if err != nil {
		return err
	}

	ip, err := r.nextAvailableMeshIP(ctx, meshID, mesh.Subnet)
	if err != nil {
		return err
	}
	member.MeshIP = ip
	member.MeshID = meshID

	query := `
		INSERT INTO mesh_members (mesh_id, user_id, peer_id, mesh_ip)
		VALUES ($1, $2, $3, $4)
		RETURNING id, joined_at
	`
	return r.pool.QueryRow(ctx, query,
		meshID, member.UserID, member.PeerID, member.MeshIP,
	).Scan(&member.ID, &member.JoinedAt)
}

// RemoveMember deletes a membership record.
func (r *MeshRepo) RemoveMember(ctx context.Context, meshID, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM mesh_members WHERE mesh_id = $1 AND user_id = $2`, meshID, userID)
	return err
}

// ListMembers returns all members of a mesh, joining with users for display name.
func (r *MeshRepo) ListMembers(ctx context.Context, meshID uuid.UUID) ([]models.MeshMember, error) {
	query := `
		SELECT m.id, m.mesh_id, m.user_id, m.peer_id, m.mesh_ip, m.joined_at,
		       COALESCE(u.display_name, u.email, '') AS display_name
		FROM mesh_members m
		JOIN users u ON u.id = m.user_id
		WHERE m.mesh_id = $1
		ORDER BY m.joined_at ASC
	`
	rows, err := r.pool.Query(ctx, query, meshID)
	if err != nil {
		return nil, fmt.Errorf("mesh: list members: %w", err)
	}
	defer rows.Close()

	var members []models.MeshMember
	for rows.Next() {
		var m models.MeshMember
		if err := rows.Scan(
			&m.ID, &m.MeshID, &m.UserID, &m.PeerID, &m.MeshIP, &m.JoinedAt, &m.DisplayName,
		); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mesh: list members rows: %w", err)
	}
	return members, nil
}

// CountMembers returns the number of members in a mesh network.
func (r *MeshRepo) CountMembers(ctx context.Context, meshID uuid.UUID) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mesh_members WHERE mesh_id = $1`, meshID,
	).Scan(&count)
	return count, err
}

// CountByOwner returns the number of mesh networks owned by the given user.
func (r *MeshRepo) CountByOwner(ctx context.Context, ownerID uuid.UUID) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mesh_networks WHERE owner_id = $1`, ownerID,
	).Scan(&count)
	return count, err
}

// UpdateMemberPeer links a member's mesh record to their active VPN peer.
func (r *MeshRepo) UpdateMemberPeer(ctx context.Context, meshID, userID uuid.UUID, peerID *uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE mesh_members SET peer_id = $3 WHERE mesh_id = $1 AND user_id = $2`,
		meshID, userID, peerID,
	)
	return err
}

// ListAll returns every mesh network in the system (admin use only).
func (r *MeshRepo) ListAll(ctx context.Context) ([]models.MeshNetwork, error) {
	query := `
		SELECT n.id, n.name, n.description, n.owner_id, n.subnet, n.invite_code,
		       n.invite_expires_at, n.max_members, n.is_active, n.created_at, n.updated_at,
		       COUNT(m.id) AS member_count, n.country_code, n.is_session
		FROM mesh_networks n
		LEFT JOIN mesh_members m ON m.mesh_id = n.id
		GROUP BY n.id
		ORDER BY n.created_at DESC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("mesh: list all: %w", err)
	}
	defer rows.Close()

	var meshes []models.MeshNetwork
	for rows.Next() {
		var mesh models.MeshNetwork
		if err := rows.Scan(
			&mesh.ID, &mesh.Name, &mesh.Description, &mesh.OwnerID, &mesh.Subnet, &mesh.InviteCode,
			&mesh.InviteExpiresAt, &mesh.MaxMembers, &mesh.IsActive, &mesh.CreatedAt, &mesh.UpdatedAt,
			&mesh.MemberCount, &mesh.CountryCode, &mesh.IsSession,
		); err != nil {
			return nil, err
		}
		meshes = append(meshes, mesh)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mesh: list all rows: %w", err)
	}
	return meshes, nil
}

// AdminMeshMember is an enriched member row returned only to admins.
type AdminMeshMember struct {
	MeshIP      string    `json:"mesh_ip"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	UserID      string    `json:"user_id"`
	PublicIP    string    `json:"public_ip"`  // peer assigned_ip (VPN tunnel IP)
	Connected   bool      `json:"connected"` // true when peer_id IS NOT NULL
	JoinedAt    time.Time `json:"joined_at"`
}

// ListMembersAdmin returns all members of a mesh with user email included,
// and a Connected flag derived from whether peer_id is set.
func (r *MeshRepo) ListMembersAdmin(ctx context.Context, meshID uuid.UUID) ([]AdminMeshMember, error) {
	query := `
		SELECT m.mesh_ip,
		       COALESCE(u.display_name, u.email, '') AS display_name,
		       u.email,
		       m.user_id::text,
		       COALESCE(p.assigned_ip, '') AS public_ip,
		       (m.peer_id IS NOT NULL) AS connected,
		       m.joined_at
		FROM mesh_members m
		JOIN users u ON u.id = m.user_id
		LEFT JOIN peers p ON p.id = m.peer_id
		WHERE m.mesh_id = $1
		ORDER BY connected DESC, m.joined_at ASC
	`
	rows, err := r.pool.Query(ctx, query, meshID)
	if err != nil {
		return nil, fmt.Errorf("mesh: list members admin: %w", err)
	}
	defer rows.Close()

	var members []AdminMeshMember
	for rows.Next() {
		var m AdminMeshMember
		if err := rows.Scan(&m.MeshIP, &m.DisplayName, &m.Email, &m.UserID, &m.PublicIP, &m.Connected, &m.JoinedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mesh: list members admin rows: %w", err)
	}
	return members, nil
}

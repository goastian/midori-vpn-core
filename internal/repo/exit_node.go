package repo

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ExitNode holds a peer's mesh-IP + proxy port that can be used as an
// exit node by other users in the same mesh.
type ExitNode struct {
	UserID      uuid.UUID `json:"user_id"`
	MeshIP      string    `json:"mesh_ip"`
	ProxyScheme string    `json:"proxy_scheme"`
	ProxyPort   int       `json:"proxy_port"`
	SupportsTCP bool      `json:"supports_tcp"`
	SupportsUDP bool      `json:"supports_udp"`
	IsActive    bool      `json:"is_active"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserExitNodeSelection is the exit node currently selected by a user.
type UserExitNodeSelection struct {
	UserID      uuid.UUID `json:"user_id"`
	MeshIP      string    `json:"mesh_ip"`
	ProxyScheme string    `json:"proxy_scheme"`
	ProxyPort   int       `json:"proxy_port"`
	SupportsTCP bool      `json:"supports_tcp"`
	SupportsUDP bool      `json:"supports_udp"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ExitNodeRepo struct {
	pool *pgxpool.Pool
}

func NewExitNodeRepo(pool *pgxpool.Pool) *ExitNodeRepo {
	return &ExitNodeRepo{pool: pool}
}

// RegisterExitNode marks a mesh member as an exit node with the given proxy capability.
// The mesh_members row is looked up by user_id + mesh_id.
func (r *ExitNodeRepo) RegisterExitNode(ctx context.Context, userID, meshID uuid.UUID, proxyScheme string, proxyPort int, supportsTCP, supportsUDP bool) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE mesh_members
		SET is_exit_node = TRUE,
		    proxy_scheme = $1,
		    proxy_port = $2,
		    supports_tcp = $3,
		    supports_udp = $4
		WHERE user_id = $5 AND mesh_id = $6`,
		proxyScheme, proxyPort, supportsTCP, supportsUDP, userID, meshID)
	return err
}

// DeregisterExitNode removes the exit-node flag for a user in a mesh.
func (r *ExitNodeRepo) DeregisterExitNode(ctx context.Context, userID, meshID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE mesh_members
		SET is_exit_node = FALSE, proxy_port = 0, supports_tcp = TRUE, supports_udp = FALSE
		WHERE user_id = $1 AND mesh_id = $2`,
		userID, meshID)
	return err
}

// ListExitNodes returns active full-tunnel exit nodes for meshes the user
// belongs to. Full-tunnel v1 requires SOCKS5 with TCP and UDP support.
func (r *ExitNodeRepo) ListExitNodes(ctx context.Context, userID uuid.UUID) ([]ExitNode, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT mm.user_id, mm.mesh_ip, mm.proxy_scheme, mm.proxy_port,
		       mm.supports_tcp, mm.supports_udp, mm.is_exit_node, mm.joined_at
		FROM mesh_members mm
		WHERE mm.is_exit_node = TRUE
		  AND mm.proxy_scheme = 'socks5'
		  AND mm.supports_tcp = TRUE
		  AND mm.supports_udp = TRUE
		  AND mm.proxy_port > 0
		  AND mm.mesh_id IN (
			  SELECT mesh_id FROM mesh_members WHERE user_id = $1
		  )
		ORDER BY mm.mesh_ip`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []ExitNode
	for rows.Next() {
		var n ExitNode
		if err := rows.Scan(
			&n.UserID, &n.MeshIP, &n.ProxyScheme, &n.ProxyPort,
			&n.SupportsTCP, &n.SupportsUDP, &n.IsActive, &n.UpdatedAt,
		); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

// SetUserExitNode records the exit node selection for a user.
func (r *ExitNodeRepo) SetUserExitNode(ctx context.Context, userID uuid.UUID, meshIP, proxyScheme string, proxyPort int, supportsTCP, supportsUDP bool) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO user_exit_node (user_id, mesh_ip, proxy_scheme, proxy_port, supports_tcp, supports_udp, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (user_id)
		DO UPDATE SET mesh_ip = EXCLUDED.mesh_ip,
		              proxy_scheme = EXCLUDED.proxy_scheme,
		              proxy_port = EXCLUDED.proxy_port,
		              supports_tcp = EXCLUDED.supports_tcp,
		              supports_udp = EXCLUDED.supports_udp,
		              updated_at = NOW()`,
		userID, meshIP, proxyScheme, proxyPort, supportsTCP, supportsUDP)
	return err
}

// GetUserExitNode returns the exit node selection for a user, or nil if none.
func (r *ExitNodeRepo) GetUserExitNode(ctx context.Context, userID uuid.UUID) (*UserExitNodeSelection, error) {
	var s UserExitNodeSelection
	err := r.pool.QueryRow(ctx, `
		SELECT user_id, mesh_ip, proxy_scheme, proxy_port, supports_tcp, supports_udp, updated_at
		FROM user_exit_node
		WHERE user_id = $1`, userID).
		Scan(&s.UserID, &s.MeshIP, &s.ProxyScheme, &s.ProxyPort, &s.SupportsTCP, &s.SupportsUDP, &s.UpdatedAt)
	if err != nil {
		return nil, err // includes pgx.ErrNoRows
	}
	return &s, nil
}

// ClearUserExitNode removes the exit node selection for a user.
func (r *ExitNodeRepo) ClearUserExitNode(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM user_exit_node WHERE user_id = $1`, userID)
	return err
}

package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

const DefaultNodeFreshness = 90 * time.Second

type MulticlusterRepo struct {
	pool *pgxpool.Pool
}

func NewMulticlusterRepo(pool *pgxpool.Pool) *MulticlusterRepo {
	return &MulticlusterRepo{pool: pool}
}

func (r *MulticlusterRepo) CreateCluster(ctx context.Context, cluster *models.Cluster) error {
	if cluster == nil || !cluster.State.Valid() {
		return errors.New("valid cluster state is required")
	}
	labels, err := json.Marshal(cluster.PolicyLabels)
	if err != nil {
		return fmt.Errorf("encode cluster policy labels: %w", err)
	}
	if cluster.PolicyLabels == nil {
		labels = []byte("{}")
	}
	return r.pool.QueryRow(ctx, `
		INSERT INTO clusters (name, region, state, policy_labels, is_principal)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at`,
		cluster.Name, cluster.Region, cluster.State, labels, cluster.IsPrincipal,
	).Scan(&cluster.ID, &cluster.CreatedAt, &cluster.UpdatedAt)
}

func (r *MulticlusterRepo) GetCluster(ctx context.Context, id uuid.UUID) (*models.Cluster, error) {
	var cluster models.Cluster
	var labels []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, region, state, policy_labels, is_principal, created_at, updated_at
		FROM clusters WHERE id = $1`, id).Scan(
		&cluster.ID, &cluster.Name, &cluster.Region, &cluster.State, &labels,
		&cluster.IsPrincipal, &cluster.CreatedAt, &cluster.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get cluster: %w", err)
	}
	if err := json.Unmarshal(labels, &cluster.PolicyLabels); err != nil {
		return nil, fmt.Errorf("decode cluster policy labels: %w", err)
	}
	return &cluster, nil
}

func (r *MulticlusterRepo) CreateNode(ctx context.Context, node *models.CoreNode) error {
	if node == nil || !node.State.Valid() {
		return errors.New("valid node state is required")
	}
	return r.pool.QueryRow(ctx, `
		INSERT INTO core_nodes (cluster_id, name, management_host, state, core_version)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, last_seen_at, created_at, updated_at`,
		node.ClusterID, node.Name, node.ManagementHost, node.State, node.CoreVersion,
	).Scan(&node.ID, &node.LastSeenAt, &node.CreatedAt, &node.UpdatedAt)
}

// BindServer attaches exactly one server inventory row to one Core node and
// permanently removes that row's temporary legacy placement exception.
func (r *MulticlusterRepo) BindServer(ctx context.Context, serverID, nodeID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE vpn_servers
		SET node_id = $2, legacy_node_unbound = FALSE, updated_at = NOW()
		WHERE id = $1`, serverID, nodeID)
	if err != nil {
		return fmt.Errorf("bind VPN server to Core node: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}

func (r *MulticlusterRepo) CreateDesiredRevision(ctx context.Context, revision *models.DesiredRevision) error {
	if revision == nil {
		return errors.New("desired revision is required")
	}
	return r.pool.QueryRow(ctx, `
		INSERT INTO desired_revisions (
			node_id, revision, previous_revision, schema_version,
			minimum_core_version, payload, payload_sha256, signature,
			signing_key_id, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at`,
		revision.NodeID, revision.Revision, revision.PreviousRevision,
		revision.SchemaVersion, revision.MinimumCoreVersion, revision.Payload,
		revision.PayloadSHA256, revision.Signature, revision.SigningKeyID,
		revision.IssuedAt, revision.ExpiresAt,
	).Scan(&revision.ID, &revision.CreatedAt)
}

// RecordObservation appends observed state and updates only the node's bounded
// summary. The historical observation itself is never overwritten.
func (r *MulticlusterRepo) RecordObservation(ctx context.Context, observation *models.NodeObservation) error {
	if observation == nil {
		return errors.New("node observation is required")
	}
	transports, err := json.Marshal(observation.TransportStates)
	if err != nil {
		return fmt.Errorf("encode node transport states: %w", err)
	}
	if observation.TransportStates == nil {
		transports = []byte("{}")
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin node observation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, `
		INSERT INTO node_observations (
			node_id, applied_revision, core_version, health_status,
			version_compatible, current_peers, max_peers, transport_states,
			last_error_code, reported_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, received_at`,
		observation.NodeID, observation.AppliedRevision, observation.CoreVersion,
		observation.HealthStatus, observation.VersionCompatible,
		observation.CurrentPeers, observation.MaxPeers, transports,
		observation.LastErrorCode, observation.ReportedAt,
	).Scan(&observation.ID, &observation.ReceivedAt); err != nil {
		return fmt.Errorf("append node observation: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core_nodes
		SET core_version = $2, last_seen_at = $3, updated_at = NOW()
		WHERE id = $1`, observation.NodeID, observation.CoreVersion, observation.ReceivedAt)
	if err != nil {
		return fmt.Errorf("update Core node observation summary: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit node observation: %w", err)
	}
	return nil
}

func (r *MulticlusterRepo) ServerPlacementEligible(ctx context.Context, serverID uuid.UUID, protocol string, freshness time.Duration) (bool, error) {
	if freshness <= 0 {
		return false, errors.New("positive node freshness is required")
	}
	var eligible bool
	if err := r.pool.QueryRow(ctx, `
		SELECT vpn_server_placement_eligible($1, NULLIF($2, ''), $3::interval, TRUE)`,
		serverID, protocol, freshness.String(),
	).Scan(&eligible); err != nil {
		return false, fmt.Errorf("evaluate server placement eligibility: %w", err)
	}
	return eligible, nil
}

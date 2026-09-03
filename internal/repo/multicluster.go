package repo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

const DefaultNodeFreshness = 90 * time.Second

const (
	minEnrollmentTokenTTL = time.Minute
	maxEnrollmentTokenTTL = 24 * time.Hour
)

var (
	ErrEnrollmentTokenInvalid  = errors.New("node enrollment token is invalid")
	ErrNodeAlreadyEnrolled     = errors.New("core node is already enrolled")
	ErrNodeNotEnrolling        = errors.New("core node is not accepting enrollment")
	ErrNodeIdentityUnavailable = errors.New("core node identity is unavailable")
	ErrNodeIdentityConflict    = errors.New("core node identity is already assigned")
	ErrNodeRevoked             = errors.New("core node or cluster is revoked")
	ErrDesiredRevisionConflict = errors.New("desired state revision conflicts with the current sequence")
)

type DesiredRevisionContext struct {
	ClusterID        uuid.UUID
	NextRevision     int64
	PreviousRevision *int64
}

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

// IssueEnrollmentToken returns the only plaintext copy of a bounded one-use
// token. PostgreSQL receives only its SHA-256 digest.
func (r *MulticlusterRepo) IssueEnrollmentToken(ctx context.Context, nodeID uuid.UUID, ttl time.Duration) (*models.NodeEnrollmentToken, error) {
	if nodeID == uuid.Nil {
		return nil, errors.New("core node ID is required")
	}
	if ttl < minEnrollmentTokenTTL || ttl > maxEnrollmentTokenTTL {
		return nil, fmt.Errorf("enrollment token TTL must be between %s and %s", minEnrollmentTokenTTL, maxEnrollmentTokenTTL)
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate enrollment token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := sha256.Sum256(tokenBytes)
	expiresAt := time.Now().UTC().Add(ttl)

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin enrollment token issuance: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var state, clusterState models.ClusterState
	var hasIdentity bool
	if err := tx.QueryRow(ctx, `
		SELECT node.state, cluster.state, node.identity_public_key IS NOT NULL
		FROM core_nodes node
		JOIN clusters cluster ON cluster.id = node.cluster_id
		WHERE node.id = $1
		FOR UPDATE OF node, cluster`, nodeID).Scan(&state, &clusterState, &hasIdentity); err != nil {
		return nil, fmt.Errorf("lock Core node for enrollment: %w", err)
	}
	if hasIdentity {
		return nil, ErrNodeAlreadyEnrolled
	}
	if state == models.ClusterStateRevoked || state == models.ClusterStateRetired ||
		clusterState == models.ClusterStateRevoked || clusterState == models.ClusterStateRetired {
		return nil, ErrNodeRevoked
	}
	if state != models.ClusterStateEnrolling {
		return nil, ErrNodeNotEnrolling
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_enrollment_tokens
		SET revoked_at = NOW()
		WHERE node_id = $1 AND used_at IS NULL AND revoked_at IS NULL`, nodeID); err != nil {
		return nil, fmt.Errorf("revoke previous enrollment token: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_enrollment_tokens (node_id, token_hash, expires_at)
		VALUES ($1, $2, $3)`, nodeID, digest[:], expiresAt); err != nil {
		return nil, fmt.Errorf("persist enrollment token hash: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit enrollment token issuance: %w", err)
	}
	return &models.NodeEnrollmentToken{NodeID: nodeID, Token: token, ExpiresAt: expiresAt}, nil
}

// EnrollNode consumes one token and binds the presented Ed25519 public key in
// the same transaction. Errors never include either credential.
func (r *MulticlusterRepo) EnrollNode(ctx context.Context, nodeID uuid.UUID, token string, publicKey ed25519.PublicKey) error {
	tokenBytes, err := decodeCanonicalRawURL(token, 32)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return ErrEnrollmentTokenInvalid
	}
	digest := sha256.Sum256(tokenBytes)

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin Core node enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var nodeState, clusterState models.ClusterState
	var hasIdentity bool
	if err := tx.QueryRow(ctx, `
		SELECT node.state, cluster.state, node.identity_public_key IS NOT NULL
		FROM core_nodes node
		JOIN clusters cluster ON cluster.id = node.cluster_id
		WHERE node.id = $1
		FOR UPDATE OF node, cluster`, nodeID).Scan(&nodeState, &clusterState, &hasIdentity); err != nil {
		return fmt.Errorf("lock Core node enrollment: %w", err)
	}
	if hasIdentity {
		return ErrNodeAlreadyEnrolled
	}
	if nodeState == models.ClusterStateRevoked || nodeState == models.ClusterStateRetired ||
		clusterState == models.ClusterStateRevoked || clusterState == models.ClusterStateRetired {
		return ErrNodeRevoked
	}
	if nodeState != models.ClusterStateEnrolling {
		return ErrNodeNotEnrolling
	}
	var tokenID uuid.UUID
	var storedDigest []byte
	var expiresAt time.Time
	if err := tx.QueryRow(ctx, `
		SELECT id, token_hash, expires_at
		FROM node_enrollment_tokens
		WHERE node_id = $1 AND used_at IS NULL AND revoked_at IS NULL
		FOR UPDATE`, nodeID).Scan(&tokenID, &storedDigest, &expiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrEnrollmentTokenInvalid
		}
		return fmt.Errorf("lock enrollment token: %w", err)
	}
	if !expiresAt.After(time.Now().UTC()) || len(storedDigest) != sha256.Size ||
		subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1 {
		return ErrEnrollmentTokenInvalid
	}
	if _, err := tx.Exec(ctx, `
		UPDATE core_nodes
		SET identity_public_key = $2, enrolled_at = NOW(), state = 'inactive', updated_at = NOW()
		WHERE id = $1`, nodeID, []byte(publicKey)); err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return ErrNodeIdentityConflict
		}
		return fmt.Errorf("bind Core node identity: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_enrollment_tokens SET used_at = NOW() WHERE id = $1`, tokenID); err != nil {
		return fmt.Errorf("consume enrollment token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Core node enrollment: %w", err)
	}
	return nil
}

// NodeIdentity returns the public key only for lifecycle states permitted to
// report heartbeat. Revoked and retired authority fails closed in PostgreSQL.
func (r *MulticlusterRepo) NodeIdentity(ctx context.Context, nodeID uuid.UUID) (ed25519.PublicKey, error) {
	var publicKey []byte
	var nodeState, clusterState models.ClusterState
	if err := r.pool.QueryRow(ctx, `
		SELECT node.identity_public_key, node.state, cluster.state
		FROM core_nodes node
		JOIN clusters cluster ON cluster.id = node.cluster_id
		WHERE node.id = $1`, nodeID).Scan(&publicKey, &nodeState, &clusterState); err != nil {
		return nil, fmt.Errorf("load Core node identity: %w", err)
	}
	if nodeState == models.ClusterStateRevoked || nodeState == models.ClusterStateRetired ||
		clusterState == models.ClusterStateRevoked || clusterState == models.ClusterStateRetired {
		return nil, ErrNodeRevoked
	}
	if nodeState == models.ClusterStateEnrolling || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrNodeIdentityUnavailable
	}
	return ed25519.PublicKey(append([]byte(nil), publicKey...)), nil
}

func (r *MulticlusterRepo) RevokeNode(ctx context.Context, nodeID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin Core node revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		UPDATE core_nodes SET state = 'revoked', updated_at = NOW()
		WHERE id = $1 AND state <> 'retired'`, nodeID)
	if err != nil {
		return fmt.Errorf("revoke Core node: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node_enrollment_tokens SET revoked_at = NOW()
		WHERE node_id = $1 AND used_at IS NULL AND revoked_at IS NULL`, nodeID); err != nil {
		return fmt.Errorf("revoke Core node enrollment tokens: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit Core node revocation: %w", err)
	}
	return nil
}

func decodeCanonicalRawURL(value string, size int) ([]byte, error) {
	if value != strings.TrimSpace(value) {
		return nil, errors.New("non-canonical base64url")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != size || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, errors.New("non-canonical base64url")
	}
	return raw, nil
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
	if revision == nil || revision.NodeID == uuid.Nil || revision.Revision < 1 {
		return errors.New("desired revision is required")
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin desired revision creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var nodeState, clusterState models.ClusterState
	var identitySize int
	if err := tx.QueryRow(ctx, `
		SELECT node.state, cluster.state, COALESCE(octet_length(node.identity_public_key), 0)
		FROM core_nodes node
		JOIN clusters cluster ON cluster.id = node.cluster_id
		WHERE node.id = $1
		FOR UPDATE OF node, cluster`, revision.NodeID).Scan(&nodeState, &clusterState, &identitySize); err != nil {
		return fmt.Errorf("lock Core node for desired revision: %w", err)
	}
	if nodeState == models.ClusterStateRevoked || nodeState == models.ClusterStateRetired ||
		clusterState == models.ClusterStateRevoked || clusterState == models.ClusterStateRetired {
		return ErrNodeRevoked
	}
	if nodeState == models.ClusterStateEnrolling || identitySize != ed25519.PublicKeySize {
		return ErrNodeIdentityUnavailable
	}
	var latest *int64
	var latestValue int64
	err = tx.QueryRow(ctx, `
		SELECT revision FROM desired_revisions WHERE node_id = $1
		ORDER BY revision DESC LIMIT 1`, revision.NodeID).Scan(&latestValue)
	if err == nil {
		latest = &latestValue
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("load latest desired revision: %w", err)
	}
	wantRevision := int64(1)
	if latest != nil {
		wantRevision = *latest + 1
	}
	if revision.Revision != wantRevision || !equalOptionalRevision(revision.PreviousRevision, latest) {
		return ErrDesiredRevisionConflict
	}
	if err := tx.QueryRow(ctx, `
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
	).Scan(&revision.ID, &revision.CreatedAt); err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && (pgError.Code == "23505" || pgError.Code == "23503" || pgError.Code == "23514") {
			return ErrDesiredRevisionConflict
		}
		return fmt.Errorf("persist desired revision: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit desired revision: %w", err)
	}
	return nil
}

func (r *MulticlusterRepo) DesiredContext(ctx context.Context, nodeID uuid.UUID) (*DesiredRevisionContext, error) {
	var result DesiredRevisionContext
	var nodeState, clusterState models.ClusterState
	var identitySize int
	var previous *int64
	if err := r.pool.QueryRow(ctx, `
		SELECT node.cluster_id, node.state, cluster.state,
		       COALESCE(octet_length(node.identity_public_key), 0), latest.revision
		FROM core_nodes node
		JOIN clusters cluster ON cluster.id = node.cluster_id
		LEFT JOIN LATERAL (
			SELECT revision FROM desired_revisions
			WHERE node_id = node.id ORDER BY revision DESC LIMIT 1
		) latest ON TRUE
		WHERE node.id = $1`, nodeID).Scan(
		&result.ClusterID, &nodeState, &clusterState,
		&identitySize, &previous,
	); err != nil {
		return nil, fmt.Errorf("load desired revision context: %w", err)
	}
	if nodeState == models.ClusterStateRevoked || nodeState == models.ClusterStateRetired ||
		clusterState == models.ClusterStateRevoked || clusterState == models.ClusterStateRetired {
		return nil, ErrNodeRevoked
	}
	if nodeState == models.ClusterStateEnrolling || identitySize != ed25519.PublicKeySize {
		return nil, ErrNodeIdentityUnavailable
	}
	result.PreviousRevision = previous
	result.NextRevision = 1
	if previous != nil {
		result.NextRevision = *previous + 1
	}
	return &result, nil
}

func (r *MulticlusterRepo) LatestDesiredRevision(ctx context.Context, nodeID uuid.UUID) (*models.DesiredRevision, error) {
	var revision models.DesiredRevision
	var nodeState, clusterState models.ClusterState
	var identitySize int
	err := r.pool.QueryRow(ctx, `
		SELECT desired.id, desired.node_id, desired.revision, desired.previous_revision, desired.schema_version,
		       desired.minimum_core_version, desired.payload, desired.payload_sha256, desired.signature,
		       desired.signing_key_id, desired.issued_at, desired.expires_at, desired.created_at,
		       node.state, cluster.state, COALESCE(octet_length(node.identity_public_key), 0)
		FROM desired_revisions desired
		JOIN core_nodes node ON node.id = desired.node_id
		JOIN clusters cluster ON cluster.id = node.cluster_id
		WHERE desired.node_id = $1
		ORDER BY desired.revision DESC LIMIT 1`, nodeID).Scan(
		&revision.ID, &revision.NodeID, &revision.Revision, &revision.PreviousRevision,
		&revision.SchemaVersion, &revision.MinimumCoreVersion, &revision.Payload,
		&revision.PayloadSHA256, &revision.Signature, &revision.SigningKeyID,
		&revision.IssuedAt, &revision.ExpiresAt, &revision.CreatedAt,
		&nodeState, &clusterState, &identitySize,
	)
	if err != nil {
		return nil, fmt.Errorf("load latest desired revision: %w", err)
	}
	if nodeState == models.ClusterStateRevoked || nodeState == models.ClusterStateRetired ||
		clusterState == models.ClusterStateRevoked || clusterState == models.ClusterStateRetired {
		return nil, ErrNodeRevoked
	}
	if nodeState == models.ClusterStateEnrolling || identitySize != ed25519.PublicKeySize {
		return nil, ErrNodeIdentityUnavailable
	}
	return &revision, nil
}

func equalOptionalRevision(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
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
	var nodeState, clusterState models.ClusterState
	var identitySize int
	if err := tx.QueryRow(ctx, `
		SELECT node.state, cluster.state, COALESCE(octet_length(node.identity_public_key), 0)
		FROM core_nodes node
		JOIN clusters cluster ON cluster.id = node.cluster_id
		WHERE node.id = $1
		FOR UPDATE OF node, cluster`, observation.NodeID).Scan(&nodeState, &clusterState, &identitySize); err != nil {
		return fmt.Errorf("authorize node observation: %w", err)
	}
	if nodeState == models.ClusterStateRevoked || nodeState == models.ClusterStateRetired ||
		clusterState == models.ClusterStateRevoked || clusterState == models.ClusterStateRetired {
		return ErrNodeRevoked
	}
	if nodeState == models.ClusterStateEnrolling || identitySize != ed25519.PublicKeySize {
		return ErrNodeIdentityUnavailable
	}
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

// TransportCredentialCluster returns the exact cluster a short-lived
// credential must name. Unlike the temporary placement compatibility path,
// credential issuance never accepts legacy unbound servers: an asymmetric
// token without a durable cluster target would defeat cross-cluster isolation.
func (r *MulticlusterRepo) TransportCredentialCluster(ctx context.Context, serverID uuid.UUID, protocol string, freshness time.Duration) (uuid.UUID, error) {
	if serverID == uuid.Nil || strings.TrimSpace(protocol) == "" || freshness <= 0 {
		return uuid.Nil, errors.New("valid server, protocol and freshness are required")
	}
	var clusterID uuid.UUID
	if err := r.pool.QueryRow(ctx, `
		SELECT node.cluster_id
		FROM vpn_servers server
		JOIN core_nodes node ON node.id = server.node_id
		WHERE server.id = $1
		  AND server.legacy_node_unbound = FALSE
		  AND vpn_server_placement_eligible(server.id, $2, $3::interval, FALSE)`,
		serverID, protocol, freshness.String(),
	).Scan(&clusterID); err != nil {
		return uuid.Nil, fmt.Errorf("resolve transport credential cluster: %w", err)
	}
	return clusterID, nil
}

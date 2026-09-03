package repo_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

func TestMulticlusterEnrollmentUsesOneTimeHashedTokens(t *testing.T) {
	pool := testPool(t)
	multicluster := repo.NewMulticlusterRepo(pool)
	cluster := createEnrollmentCluster(t, pool, multicluster)
	node := createEnrollmentNode(t, multicluster, cluster.ID)

	first, err := multicluster.IssueEnrollmentToken(context.Background(), node.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueEnrollmentToken first: %v", err)
	}
	second, err := multicluster.IssueEnrollmentToken(context.Background(), node.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueEnrollmentToken second: %v", err)
	}
	if first.Token == second.Token {
		t.Fatal("token rotation returned the same credential")
	}

	firstBytes, _ := base64.RawURLEncoding.DecodeString(first.Token)
	firstDigest := sha256.Sum256(firstBytes)
	var firstStored []byte
	var firstRevokedAt *time.Time
	if err := pool.QueryRow(context.Background(), `
		SELECT token_hash, revoked_at FROM node_enrollment_tokens
		WHERE node_id = $1 ORDER BY created_at ASC LIMIT 1`, node.ID).Scan(&firstStored, &firstRevokedAt); err != nil {
		t.Fatal(err)
	}
	if string(firstStored) != string(firstDigest[:]) || firstRevokedAt == nil {
		t.Fatal("rotated token was not stored as a revoked SHA-256 digest")
	}
	if string(firstStored) == first.Token {
		t.Fatal("database stored the plaintext enrollment token")
	}

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := multicluster.EnrollNode(context.Background(), node.ID, first.Token, publicKey); !errors.Is(err, repo.ErrEnrollmentTokenInvalid) {
		t.Fatalf("rotated token error = %v; want ErrEnrollmentTokenInvalid", err)
	}
	if err := multicluster.EnrollNode(context.Background(), node.ID, second.Token, publicKey); err != nil {
		t.Fatalf("EnrollNode: %v", err)
	}
	storedKey, err := multicluster.NodeIdentity(context.Background(), node.ID)
	if err != nil {
		t.Fatalf("NodeIdentity: %v", err)
	}
	if string(storedKey) != string(publicKey) {
		t.Fatal("stored node public key differs from enrolled key")
	}
	var state models.ClusterState
	var enrolledAt, usedAt *time.Time
	if err := pool.QueryRow(context.Background(), `
		SELECT node.state, node.enrolled_at, token.used_at
		FROM core_nodes node
		JOIN node_enrollment_tokens token ON token.node_id = node.id
		WHERE node.id = $1 AND token.revoked_at IS NULL`, node.ID).Scan(&state, &enrolledAt, &usedAt); err != nil {
		t.Fatal(err)
	}
	if state != models.ClusterStateInactive || enrolledAt == nil || usedAt == nil {
		t.Fatalf("enrollment state = %q, enrolled=%v, used=%v", state, enrolledAt, usedAt)
	}
	if err := multicluster.EnrollNode(context.Background(), node.ID, second.Token, publicKey); !errors.Is(err, repo.ErrNodeAlreadyEnrolled) {
		t.Fatalf("reused token error = %v; want ErrNodeAlreadyEnrolled", err)
	}
}

func TestMulticlusterEnrollmentRejectsExpiredRevokedAndDuplicateIdentity(t *testing.T) {
	pool := testPool(t)
	multicluster := repo.NewMulticlusterRepo(pool)
	cluster := createEnrollmentCluster(t, pool, multicluster)

	firstNode := createEnrollmentNode(t, multicluster, cluster.ID)
	firstToken, err := multicluster.IssueEnrollmentToken(context.Background(), firstNode.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := multicluster.EnrollNode(context.Background(), firstNode.ID, firstToken.Token, publicKey); err != nil {
		t.Fatal(err)
	}

	duplicateNode := createEnrollmentNode(t, multicluster, cluster.ID)
	duplicateToken, err := multicluster.IssueEnrollmentToken(context.Background(), duplicateNode.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := multicluster.EnrollNode(context.Background(), duplicateNode.ID, duplicateToken.Token, publicKey); !errors.Is(err, repo.ErrNodeIdentityConflict) {
		t.Fatalf("duplicate identity error = %v; want ErrNodeIdentityConflict", err)
	}

	expiredNode := createEnrollmentNode(t, multicluster, cluster.ID)
	expiredToken, err := multicluster.IssueEnrollmentToken(context.Background(), expiredNode.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE node_enrollment_tokens
		SET created_at = NOW() - INTERVAL '2 minutes', expires_at = NOW() - INTERVAL '1 minute'
		WHERE node_id = $1`, expiredNode.ID); err != nil {
		t.Fatal(err)
	}
	otherPublicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := multicluster.EnrollNode(context.Background(), expiredNode.ID, expiredToken.Token, otherPublicKey); !errors.Is(err, repo.ErrEnrollmentTokenInvalid) {
		t.Fatalf("expired token error = %v; want ErrEnrollmentTokenInvalid", err)
	}

	revokedNode := createEnrollmentNode(t, multicluster, cluster.ID)
	revokedToken, err := multicluster.IssueEnrollmentToken(context.Background(), revokedNode.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := multicluster.RevokeNode(context.Background(), revokedNode.ID); err != nil {
		t.Fatal(err)
	}
	if err := multicluster.EnrollNode(context.Background(), revokedNode.ID, revokedToken.Token, otherPublicKey); !errors.Is(err, repo.ErrNodeRevoked) {
		t.Fatalf("revoked node error = %v; want ErrNodeRevoked", err)
	}
	var revokedAt *time.Time
	if err := pool.QueryRow(context.Background(), `
		SELECT revoked_at FROM node_enrollment_tokens WHERE node_id = $1`, revokedNode.ID).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt == nil {
		t.Fatal("node revocation left an enrollment token usable")
	}

	if err := multicluster.RevokeNode(context.Background(), firstNode.ID); err != nil {
		t.Fatal(err)
	}
	observation := &models.NodeObservation{
		NodeID: firstNode.ID, CoreVersion: "2.0.0", HealthStatus: "healthy",
		MaxPeers: 100, TransportStates: map[string]models.NodeTransportState{}, ReportedAt: time.Now().UTC(),
	}
	if err := multicluster.RecordObservation(context.Background(), observation); !errors.Is(err, repo.ErrNodeRevoked) {
		t.Fatalf("revoked observation error = %v; want ErrNodeRevoked", err)
	}
}

func createEnrollmentCluster(t *testing.T, pool *pgxpool.Pool, multicluster *repo.MulticlusterRepo) *models.Cluster {
	t.Helper()
	cluster := &models.Cluster{
		Name: "enrollment-" + uuid.NewString(), Region: "test", State: models.ClusterStateInactive,
	}
	if err := multicluster.CreateCluster(context.Background(), cluster); err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id = $1`, cluster.ID)
	})
	return cluster
}

func createEnrollmentNode(t *testing.T, multicluster *repo.MulticlusterRepo, clusterID uuid.UUID) *models.CoreNode {
	t.Helper()
	node := &models.CoreNode{
		ClusterID: clusterID, Name: "node-" + uuid.NewString(),
		ManagementHost: uuid.NewString() + ".nodes.test.invalid", State: models.ClusterStateEnrolling,
	}
	if err := multicluster.CreateNode(context.Background(), node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	return node
}

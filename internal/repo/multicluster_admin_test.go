package repo_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

func TestMulticlusterAdminPagesExposeOnlySafeOperationalState(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	fleet := repo.NewMulticlusterRepo(pool)
	prefix := "admin-" + uuid.NewString()
	cluster := &models.Cluster{
		Name: prefix, Region: "test-region", State: models.ClusterStateInactive,
		PolicyLabels: map[string]string{"tier": "regional"},
	}
	if err := fleet.CreateCluster(ctx, cluster); err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	node := &models.CoreNode{
		ClusterID: cluster.ID, Name: "node-" + uuid.NewString()[:8],
		ManagementHost: uuid.NewString() + ".nodes.test.invalid", State: models.ClusterStateEnrolling,
	}
	if err := fleet.CreateNode(ctx, node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := fleet.IssueEnrollmentToken(ctx, node.ID, 15*time.Minute); err != nil {
		t.Fatalf("IssueEnrollmentToken: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM node_enrollment_tokens WHERE node_id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM core_nodes WHERE id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id = $1`, cluster.ID)
	})

	clusters, total, err := fleet.ListAdminClusters(ctx, repo.ListOptions{
		Limit: 10, Search: prefix, Status: "inactive", Sort: "name", Order: "asc",
	})
	if err != nil {
		t.Fatalf("ListAdminClusters: %v", err)
	}
	if total != 1 || len(clusters) != 1 || clusters[0].ID != cluster.ID ||
		clusters[0].NodeCount != 1 || clusters[0].ActiveNodeCount != 0 ||
		clusters[0].HealthyNodeCount != 0 || clusters[0].PolicyLabels["tier"] != "regional" {
		t.Fatalf("unexpected cluster admin page: total=%d items=%#v", total, clusters)
	}

	nodes, total, err := fleet.ListAdminNodes(ctx, cluster.ID, repo.ListOptions{
		Limit: 10, Search: node.Name, Status: "enrolling", Sort: "created_at", Order: "desc",
	})
	if err != nil {
		t.Fatalf("ListAdminNodes: %v", err)
	}
	if total != 1 || len(nodes) != 1 || nodes[0].ID != node.ID || nodes[0].Enrolled ||
		nodes[0].PlacementReady || nodes[0].PlacementReason != "cluster_not_active" ||
		len(nodes[0].TransportStates) != 0 {
		t.Fatalf("unexpected node admin page: total=%d items=%#v", total, nodes)
	}

	encoded, err := json.Marshal(nodes[0])
	if err != nil {
		t.Fatalf("marshal node summary: %v", err)
	}
	for _, forbidden := range []string{"token_hash", "identity_public_key", "payload_sha256", "signature"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("admin node summary exposed %q: %s", forbidden, encoded)
		}
	}

	if _, err := pool.Exec(ctx, `UPDATE clusters SET state = 'revoked' WHERE id = $1`, cluster.ID); err != nil {
		t.Fatalf("revoke cluster fixture: %v", err)
	}
	blockedNode := &models.CoreNode{
		ClusterID: cluster.ID, Name: "blocked-" + uuid.NewString()[:8],
		ManagementHost: uuid.NewString() + ".nodes.test.invalid", State: models.ClusterStateEnrolling,
	}
	if err := fleet.CreateNode(ctx, blockedNode); !errors.Is(err, repo.ErrClusterUnavailable) {
		t.Fatalf("CreateNode on revoked cluster error = %v, want ErrClusterUnavailable", err)
	}
}

func TestUpdateUnenrolledNodeManagementHostLocksAfterEnrollment(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	fleet := repo.NewMulticlusterRepo(pool)
	cluster := &models.Cluster{
		Name: "host-update-" + uuid.NewString(), Region: "test-region", State: models.ClusterStateInactive,
	}
	if err := fleet.CreateCluster(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	node := &models.CoreNode{
		ClusterID: cluster.ID, Name: "node-" + uuid.NewString()[:8],
		ManagementHost: uuid.NewString() + ".nodes.test.invalid", State: models.ClusterStateEnrolling,
	}
	if err := fleet.CreateNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM node_enrollment_tokens WHERE node_id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM core_nodes WHERE id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id = $1`, cluster.ID)
	})
	updated, err := fleet.UpdateUnenrolledNodeManagementHost(ctx, node.ID, "10.254.240.2")
	if err != nil {
		t.Fatal(err)
	}
	if updated.ManagementHost != "10.254.240.2" || updated.State != models.ClusterStateEnrolling {
		t.Fatalf("updated node = %#v", updated)
	}
	token, err := fleet.IssueEnrollmentToken(ctx, node.ID, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := fleet.EnrollNode(ctx, node.ID, token.Token, publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.UpdateUnenrolledNodeManagementHost(ctx, node.ID, "10.254.240.3"); !errors.Is(err, repo.ErrNodeManagementImmutable) {
		t.Fatalf("enrolled update error = %v, want immutable", err)
	}
	if _, err := fleet.UpdateUnenrolledNodeManagementHost(ctx, uuid.New(), "10.254.240.3"); !errors.Is(err, repo.ErrNodeNotFound) {
		t.Fatalf("missing node update error = %v, want not found", err)
	}
}

package repo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

func TestMulticlusterPlacementRequiresCurrentHealthyObservedState(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	multiclusterRepo := repo.NewMulticlusterRepo(pool)
	serverRepo := repo.NewServerRepo(pool)

	cluster := &models.Cluster{
		Name:         "cluster-" + uuid.NewString(),
		Region:       "test-region",
		State:        models.ClusterStateActive,
		PolicyLabels: map[string]string{"tier": "regional"},
	}
	if err := multiclusterRepo.CreateCluster(ctx, cluster); err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	node := &models.CoreNode{
		ClusterID:      cluster.ID,
		Name:           "node-" + uuid.NewString()[:8],
		ManagementHost: uuid.NewString() + ".nodes.test.invalid",
		State:          models.ClusterStateActive,
	}
	if err := multiclusterRepo.CreateNode(ctx, node); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	checkedAt := time.Now().UTC()
	server := &models.VPNServer{
		Name:        "Modeled " + uuid.NewString(),
		Host:        "modeled.test.invalid",
		Endpoint:    "modeled.test.invalid",
		Port:        8443,
		WGPort:      51820,
		PublicKey:   "test-public-key",
		Location:    "Test Region",
		CountryCode: "ZZ",
		MaxPeers:    10,
		IsActive:    true,
	}
	transports := []models.TransportCapability{{
		Protocol:     "wireguard",
		Host:         "modeled.test.invalid",
		Port:         51820,
		Enabled:      true,
		Priority:     100,
		HealthStatus: "healthy",
		LastChecked:  &checkedAt,
	}}
	if err := serverRepo.CreateWithTransports(ctx, server, transports); err != nil {
		t.Fatalf("CreateWithTransports: %v", err)
	}

	legacyServer := &models.VPNServer{
		Name:              "Legacy " + uuid.NewString(),
		Host:              "legacy.test.invalid",
		Endpoint:          "legacy.test.invalid",
		Port:              8443,
		WGPort:            51820,
		PublicKey:         "legacy-public-key",
		Location:          "Test Region",
		CountryCode:       "ZZ",
		MaxPeers:          10,
		IsActive:          true,
		LegacyNodeUnbound: true,
	}
	if err := serverRepo.CreateWithTransports(ctx, legacyServer, transports); err != nil {
		t.Fatalf("create legacy server: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id IN ($1, $2)`, server.ID, legacyServer.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM node_observations WHERE node_id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM desired_revisions WHERE node_id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM node_enrollment_tokens WHERE node_id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM core_nodes WHERE id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id = $1`, cluster.ID)
	})

	assertEligibility := func(want bool, label string) {
		t.Helper()
		eligible, err := multiclusterRepo.ServerPlacementEligible(ctx, server.ID, "wireguard", repo.DefaultNodeFreshness)
		if err != nil {
			t.Fatalf("ServerPlacementEligible (%s): %v", label, err)
		}
		if eligible != want {
			t.Fatalf("ServerPlacementEligible (%s) = %v, want %v", label, eligible, want)
		}
	}

	assertEligibility(false, "new unbound server")
	if err := multiclusterRepo.BindServer(ctx, server.ID, node.ID); err != nil {
		t.Fatalf("BindServer: %v", err)
	}
	loadedServer, err := serverRepo.GetByID(ctx, server.ID)
	if err != nil {
		t.Fatalf("GetByID after binding: %v", err)
	}
	if loadedServer.NodeID == nil || *loadedServer.NodeID != node.ID || loadedServer.LegacyNodeUnbound {
		t.Fatalf("server binding was not persisted: %#v", loadedServer)
	}
	if err := multiclusterRepo.BindServer(ctx, legacyServer.ID, node.ID); err == nil {
		t.Fatal("one Core node was bound to more than one VPN server")
	}

	assertEligibility(false, "no desired or observed state")
	issuedAt := time.Now().UTC().Add(-time.Minute)
	revision := &models.DesiredRevision{
		NodeID:             node.ID,
		Revision:           1,
		SchemaVersion:      1,
		MinimumCoreVersion: "2.0.0",
		Payload:            []byte(`{"schema_version":1}`),
		PayloadSHA256:      make([]byte, 32),
		Signature:          make([]byte, 64),
		SigningKeyID:       "test-signing-key",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(10 * time.Minute),
	}
	if err := multiclusterRepo.CreateDesiredRevision(ctx, revision); err != nil {
		t.Fatalf("CreateDesiredRevision: %v", err)
	}
	revisionNumber := revision.Revision
	observation := &models.NodeObservation{
		NodeID:            node.ID,
		AppliedRevision:   &revisionNumber,
		CoreVersion:       "2.0.0",
		HealthStatus:      "healthy",
		VersionCompatible: true,
		CurrentPeers:      0,
		MaxPeers:          10,
		TransportStates: map[string]models.NodeTransportState{
			"wireguard": {Status: "healthy", Certified: true},
		},
		ReportedAt: time.Now().UTC(),
	}
	if err := multiclusterRepo.RecordObservation(ctx, observation); err != nil {
		t.Fatalf("RecordObservation: %v", err)
	}
	assertEligibility(true, "matching healthy observation")

	loadedCluster, err := multiclusterRepo.GetCluster(ctx, cluster.ID)
	if err != nil || loadedCluster.PolicyLabels["tier"] != "regional" {
		t.Fatalf("GetCluster did not preserve labels: cluster=%#v err=%v", loadedCluster, err)
	}

	if _, err := pool.Exec(ctx, `UPDATE clusters SET state = 'inactive' WHERE id = $1`, cluster.ID); err != nil {
		t.Fatalf("set cluster inactive: %v", err)
	}
	assertEligibility(false, "inactive cluster")
	_, _ = pool.Exec(ctx, `UPDATE clusters SET state = 'active' WHERE id = $1`, cluster.ID)

	if _, err := pool.Exec(ctx, `UPDATE core_nodes SET state = 'draining' WHERE id = $1`, node.ID); err != nil {
		t.Fatalf("set node draining: %v", err)
	}
	assertEligibility(false, "draining node")
	_, _ = pool.Exec(ctx, `UPDATE core_nodes SET state = 'active' WHERE id = $1`, node.ID)

	if _, err := pool.Exec(ctx, `
		UPDATE core_nodes
		SET created_at = NOW() - INTERVAL '10 minutes', last_seen_at = NOW() - INTERVAL '5 minutes'
		WHERE id = $1`, node.ID); err != nil {
		t.Fatalf("make node heartbeat stale: %v", err)
	}
	assertEligibility(false, "stale heartbeat")
	_, _ = pool.Exec(ctx, `UPDATE core_nodes SET last_seen_at = NOW() WHERE id = $1`, node.ID)

	if _, err := pool.Exec(ctx, `UPDATE node_observations SET version_compatible = FALSE WHERE id = $1`, observation.ID); err != nil {
		t.Fatalf("mark version incompatible: %v", err)
	}
	assertEligibility(false, "incompatible version")
	_, _ = pool.Exec(ctx, `UPDATE node_observations SET version_compatible = TRUE WHERE id = $1`, observation.ID)

	if _, err := pool.Exec(ctx, `
		UPDATE node_observations
		SET transport_states = '{"wireguard":{"status":"healthy","certified":false}}'::jsonb
		WHERE id = $1`, observation.ID); err != nil {
		t.Fatalf("remove transport certification: %v", err)
	}
	assertEligibility(false, "uncertified observed transport")
	_, _ = pool.Exec(ctx, `
		UPDATE node_observations
		SET transport_states = '{"wireguard":{"status":"healthy","certified":true}}'::jsonb
		WHERE id = $1`, observation.ID)

	if _, err := pool.Exec(ctx, `UPDATE vpn_server_transports SET health_status = 'degraded' WHERE server_id = $1`, server.ID); err != nil {
		t.Fatalf("degrade inventory transport: %v", err)
	}
	assertEligibility(false, "degraded inventory transport")
	_, _ = pool.Exec(ctx, `UPDATE vpn_server_transports SET health_status = 'healthy' WHERE server_id = $1`, server.ID)

	if _, err := pool.Exec(ctx, `UPDATE vpn_servers SET current_peers = max_peers WHERE id = $1`, server.ID); err != nil {
		t.Fatalf("fill server capacity: %v", err)
	}
	assertEligibility(false, "full server")
	var replacementEligible bool
	if err := pool.QueryRow(ctx, `
		SELECT vpn_server_placement_eligible($1, 'wireguard', INTERVAL '90 seconds', FALSE)`,
		server.ID).Scan(&replacementEligible); err != nil {
		t.Fatalf("evaluate replacement eligibility: %v", err)
	}
	if !replacementEligible {
		t.Fatal("same-server replacement was blocked only because capacity was full")
	}
	_, _ = pool.Exec(ctx, `UPDATE vpn_servers SET current_peers = 0 WHERE id = $1`, server.ID)

	previousRevision := revision.Revision
	missingRevision := int64(999)
	invalidRevision := &models.DesiredRevision{
		NodeID:             node.ID,
		Revision:           2,
		PreviousRevision:   &missingRevision,
		SchemaVersion:      1,
		MinimumCoreVersion: "2.0.0",
		Payload:            []byte(`{"schema_version":1,"revision":2}`),
		PayloadSHA256:      make([]byte, 32),
		Signature:          make([]byte, 64),
		SigningKeyID:       "test-signing-key",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(10 * time.Minute),
	}
	if err := multiclusterRepo.CreateDesiredRevision(ctx, invalidRevision); err == nil {
		t.Fatal("desired revision accepted a missing previous revision")
	}
	revision2 := &models.DesiredRevision{
		NodeID:             node.ID,
		Revision:           2,
		PreviousRevision:   &previousRevision,
		SchemaVersion:      1,
		MinimumCoreVersion: "2.0.0",
		Payload:            []byte(`{"schema_version":1,"revision":2}`),
		PayloadSHA256:      make([]byte, 32),
		Signature:          make([]byte, 64),
		SigningKeyID:       "test-signing-key",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(10 * time.Minute),
	}
	if err := multiclusterRepo.CreateDesiredRevision(ctx, revision2); err != nil {
		t.Fatalf("CreateDesiredRevision 2: %v", err)
	}
	assertEligibility(false, "desired and observed revision drift")
	revisionNumber = revision2.Revision
	observation2 := &models.NodeObservation{
		NodeID:            node.ID,
		AppliedRevision:   &revisionNumber,
		CoreVersion:       "2.0.0",
		HealthStatus:      "healthy",
		VersionCompatible: true,
		CurrentPeers:      0,
		MaxPeers:          10,
		TransportStates: map[string]models.NodeTransportState{
			"wireguard": {Status: "healthy", Certified: true},
		},
		ReportedAt: time.Now().UTC(),
	}
	if err := multiclusterRepo.RecordObservation(ctx, observation2); err != nil {
		t.Fatalf("RecordObservation 2: %v", err)
	}
	assertEligibility(true, "latest revision observed")

	if _, err := pool.Exec(ctx, `UPDATE desired_revisions SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, revision2.ID); err != nil {
		t.Fatalf("expire desired revision: %v", err)
	}
	assertEligibility(false, "expired desired revision")
	_, _ = pool.Exec(ctx, `UPDATE desired_revisions SET expires_at = NOW() + INTERVAL '10 minutes' WHERE id = $1`, revision2.ID)

	if _, err := pool.Exec(ctx, `
		INSERT INTO node_enrollment_tokens (node_id, token_hash, expires_at)
		VALUES ($1, $2, NOW() + INTERVAL '10 minutes')`, node.ID, make([]byte, 32)); err != nil {
		t.Fatalf("insert enrollment token hash: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO node_enrollment_tokens (node_id, token_hash, expires_at)
		VALUES ($1, $2, NOW() + INTERVAL '10 minutes')`, node.ID, make([]byte, 31)); err == nil {
		t.Fatal("invalid enrollment token hash length was accepted")
	}
	var plaintextColumnCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'node_enrollment_tokens'
		  AND column_name IN ('token', 'plaintext_token')`).Scan(&plaintextColumnCount); err != nil {
		t.Fatalf("inspect enrollment token columns: %v", err)
	}
	if plaintextColumnCount != 0 {
		t.Fatal("enrollment token plaintext column exists")
	}

	var observationCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM node_observations WHERE node_id = $1`, node.ID).Scan(&observationCount); err != nil {
		t.Fatalf("count observation history: %v", err)
	}
	if observationCount != 2 {
		t.Fatalf("observation history count = %d, want 2", observationCount)
	}
	var lastSeen *time.Time
	var coreVersion string
	if err := pool.QueryRow(ctx, `SELECT last_seen_at, core_version FROM core_nodes WHERE id = $1`, node.ID).Scan(&lastSeen, &coreVersion); err != nil {
		t.Fatalf("load node summary: %v", err)
	}
	if lastSeen == nil || coreVersion != "2.0.0" {
		t.Fatalf("node summary was not updated: last_seen=%v version=%q", lastSeen, coreVersion)
	}

	legacyEligible, err := multiclusterRepo.ServerPlacementEligible(ctx, legacyServer.ID, "wireguard", repo.DefaultNodeFreshness)
	if err != nil || !legacyEligible {
		t.Fatalf("explicit historical migration exception is not usable: eligible=%v err=%v", legacyEligible, err)
	}
	if err := multiclusterRepo.BindServer(ctx, uuid.New(), node.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("binding an unknown server returned %v, want pgx.ErrNoRows", err)
	}
}

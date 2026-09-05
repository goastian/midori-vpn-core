package repo_test

import (
	"context"
	"crypto/rand"
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
	identityPublicKey := make([]byte, 32)
	if _, err := rand.Read(identityPublicKey); err != nil {
		t.Fatalf("generate node identity fixture: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE core_nodes SET identity_public_key = $2, enrolled_at = NOW()
		WHERE id = $1`, node.ID, identityPublicKey); err != nil {
		t.Fatalf("enroll node identity fixture: %v", err)
	}

	checkedAt := time.Now().UTC()
	server := &models.VPNServer{
		Name:        "Modeled " + uuid.NewString(),
		Host:        "modeled.test.invalid",
		ProbeURL:    "https://modeled.test.invalid/.well-known/midorivpn/edge-health",
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
	}, {
		Protocol:     "openvpn",
		Host:         "modeled.test.invalid",
		Port:         1194,
		Enabled:      true,
		Priority:     90,
		HealthStatus: "healthy",
		LastChecked:  &checkedAt,
		Metadata:     map[string]interface{}{"certified": false},
	}}
	if err := serverRepo.CreateWithTransports(ctx, server, transports); err != nil {
		t.Fatalf("CreateWithTransports: %v", err)
	}

	legacyServer := &models.VPNServer{
		Name:              "Legacy " + uuid.NewString(),
		Host:              "legacy.test.invalid",
		ProbeURL:          "https://legacy.test.invalid/.well-known/midorivpn/edge-health",
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
		Payload:            []byte(`{"transports":[{"enabled":true,"protocol":"openvpn"},{"enabled":true,"protocol":"wireguard"}]}`),
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
			"wireguard": {Status: "healthy", Certified: false},
		},
		ReportedAt: time.Now().UTC(),
	}
	if err := multiclusterRepo.RecordObservation(ctx, observation); err != nil {
		t.Fatalf("RecordObservation: %v", err)
	}
	// Migration 7 historically allowed a duplicated port in endpoint. The
	// placement contract must expose a host so clients can join it exactly once.
	if _, err := pool.Exec(ctx, `
		UPDATE vpn_server_transports
		SET endpoint = 'modeled.test.invalid:51820'
		WHERE server_id = $1 AND protocol = 'wireguard'`, server.ID); err != nil {
		t.Fatalf("seed historical transport endpoint: %v", err)
	}
	assertEligibility(true, "matching healthy observation")
	candidates, err := serverRepo.ListCandidates(ctx, "wireguard", repo.DefaultNodeFreshness)
	if err != nil {
		t.Fatalf("ListCandidates: %v", err)
	}
	if len(candidates) != 1 || candidates[0].ID != server.ID || candidates[0].Protocol != "wireguard" ||
		candidates[0].ProbeURL != server.ProbeURL || candidates[0].Endpoint != "modeled.test.invalid" {
		t.Fatalf("fail-closed candidates = %#v, want only modeled server", candidates)
	}
	openVPNEligible, err := multiclusterRepo.ServerPlacementEligible(ctx, server.ID, "openvpn", repo.DefaultNodeFreshness)
	if err != nil || openVPNEligible {
		t.Fatalf("uncertified central OpenVPN state must be ineligible: eligible=%v err=%v", openVPNEligible, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE vpn_server_transports
		SET metadata = jsonb_set(metadata, '{certified}', 'true'::jsonb), last_checked_at = NOW()
		WHERE server_id = $1 AND protocol = 'openvpn'`, server.ID); err != nil {
		t.Fatalf("certify central OpenVPN state: %v", err)
	}
	openVPNEligible, err = multiclusterRepo.ServerPlacementEligible(ctx, server.ID, "openvpn", repo.DefaultNodeFreshness)
	if err != nil || !openVPNEligible {
		t.Fatalf("centrally certified OpenVPN state must be eligible: eligible=%v err=%v", openVPNEligible, err)
	}
	openVPNCandidates, err := serverRepo.ListCandidates(ctx, "openvpn", repo.DefaultNodeFreshness)
	if err != nil || len(openVPNCandidates) != 1 || openVPNCandidates[0].ID != server.ID {
		t.Fatalf("centrally certified OpenVPN candidate missing: candidates=%#v err=%v", openVPNCandidates, err)
	}
	credentialClusterID, err := multiclusterRepo.TransportCredentialCluster(ctx, server.ID, "wireguard", repo.DefaultNodeFreshness)
	if err != nil || credentialClusterID != cluster.ID {
		t.Fatalf("TransportCredentialCluster = %s, %v; want %s", credentialClusterID, err, cluster.ID)
	}

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
		t.Fatalf("record non-certifying node observation: %v", err)
	}
	assertEligibility(true, "node observation cannot revoke central eligibility")
	_, _ = pool.Exec(ctx, `
		UPDATE desired_revisions
		SET payload = '{"transports":[{"enabled":true,"protocol":"openvpn"}]}'::jsonb
		WHERE id = $1`, revision.ID)
	assertEligibility(false, "transport absent from desired state")
	_, _ = pool.Exec(ctx, `
		UPDATE desired_revisions
		SET payload = '{"transports":[{"enabled":true,"protocol":"openvpn"},{"enabled":true,"protocol":"wireguard"}]}'::jsonb
		WHERE id = $1`, revision.ID)

	if _, err := pool.Exec(ctx, `UPDATE vpn_server_transports SET health_status = 'degraded' WHERE server_id = $1`, server.ID); err != nil {
		t.Fatalf("degrade inventory transport: %v", err)
	}
	assertEligibility(false, "degraded inventory transport")
	_, _ = pool.Exec(ctx, `UPDATE vpn_server_transports SET health_status = 'healthy' WHERE server_id = $1`, server.ID)

	if _, err := pool.Exec(ctx, `UPDATE vpn_servers SET current_peers = max_peers WHERE id = $1`, server.ID); err != nil {
		t.Fatalf("fill server capacity: %v", err)
	}
	assertEligibility(false, "full server")
	candidates, err = serverRepo.ListCandidates(ctx, "wireguard", repo.DefaultNodeFreshness)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("full server remained a candidate: candidates=%#v err=%v", candidates, err)
	}
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
		Payload:            []byte(`{"revision":2,"transports":[{"enabled":true,"protocol":"openvpn"},{"enabled":true,"protocol":"wireguard"}]}`),
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
		Payload:            []byte(`{"revision":2,"transports":[{"enabled":true,"protocol":"openvpn"},{"enabled":true,"protocol":"wireguard"}]}`),
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
			"wireguard": {Status: "healthy", Certified: false},
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
	if _, err := multiclusterRepo.TransportCredentialCluster(ctx, legacyServer.ID, "wireguard", repo.DefaultNodeFreshness); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("legacy server received an asymmetric credential scope: %v", err)
	}
	if err := multiclusterRepo.BindServer(ctx, uuid.New(), node.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("binding an unknown server returned %v, want pgx.ErrNoRows", err)
	}
}

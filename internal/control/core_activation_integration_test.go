package control_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

type coreActivationFixture struct {
	pool                  *pgxpool.Pool
	cluster, node, server uuid.UUID
	sql                   string
	migratorRole          string
}

// Create the inventory through the actual admin handlers: fresh API servers
// must not inherit the historical legacy_node_unbound placement exception.
func newCoreActivationFixture(t *testing.T) coreActivationFixture {
	t.Helper()
	pool := handlerTestPool(t)
	ctx := context.Background()
	admin := insertUser(t, pool)
	admin.Groups = []string{"vpn-admins"}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handler := control.NewHandler(pool, &config.Config{
		AppEnv: "development", PublicBaseURL: "https://control.test",
		ControlNodeID: "control", ControlNodePrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
	})
	create := func(fn http.HandlerFunc, body any, param, value string) *httptest.ResponseRecorder {
		request := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/admin/", jsonBody(t, body)), admin)
		if param != "" {
			request = withChiParam(request, param, value)
		}
		recorder := httptest.NewRecorder()
		fn(recorder, request)
		if recorder.Code != http.StatusCreated {
			t.Fatalf("admin create: status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		return recorder
	}
	cluster := decodeResponseData[models.Cluster](t, create(handler.AdminCreateCluster, map[string]any{
		"name": "activation-" + uuid.NewString(), "region": "test",
	}, "", ""))
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, cluster.ID); err != nil {
			t.Error(err)
		}
	})
	node := decodeResponseData[models.CoreNode](t, create(handler.AdminCreateCoreNode, map[string]any{
		"name": "activation-" + uuid.NewString()[:8], "management_host": uuid.NewString() + ".nodes.test.invalid",
	}, "clusterID", cluster.ID.String()))
	t.Cleanup(func() {
		for _, table := range []string{"node_observations", "desired_revisions", "node_enrollment_tokens"} {
			if _, err := pool.Exec(ctx, "DELETE FROM "+table+" WHERE node_id = $1", node.ID); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(ctx, `DELETE FROM core_nodes WHERE id = $1`, node.ID); err != nil {
			t.Error(err)
		}
	})
	server := decodeResponseData[models.VPNServer](t, create(handler.AdminCreateServer, map[string]any{
		"name": "Activation " + uuid.NewString(), "host": "activation.test.invalid", "port": 8443,
		"probe_url":  "https://activation.test.invalid/.well-known/midorivpn/edge-health",
		"public_key": base64.StdEncoding.EncodeToString(make([]byte, 32)), "max_peers": 10,
		"transports": []map[string]any{{
			"protocol": "wireguard", "host": "activation.test.invalid", "port": 51820, "enabled": true, "priority": 10,
		}},
	}, "", ""))
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM vpn_servers WHERE id = $1`, server.ID); err != nil {
			t.Error(err)
		}
	})
	fleet := repo.NewMulticlusterRepo(pool)
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
	create(handler.AdminCreateDesiredState, map[string]any{
		"expected_previous_revision": nil, "expires_in_seconds": 600, "minimum_core_version": "2.0.0",
		"public_endpoints": []map[string]any{{"name": "wg", "host": "activation.test.invalid", "port": 51820}},
		"capacity":         map[string]any{"max_peers": 10}, "secret_references": []any{},
		"transports": []map[string]any{{
			"protocol": "wireguard", "enabled": true, "priority": 10, "endpoint": "wg", "secret_references": []string{},
		}},
	}, "nodeID", node.ID.String())
	if err := fleet.RecordObservation(ctx, &models.NodeObservation{
		NodeID: node.ID, AppliedRevision: int64Pointer(1), CoreVersion: "2.0.0", HealthStatus: "healthy",
		VersionCompatible: true, MaxPeers: 10, ReportedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "postgres", "activate-core.sql"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := coreActivationFixture{pool: pool, cluster: cluster.ID, node: node.ID, server: server.ID, sql: string(contents)}
	fixture.exec(t, `UPDATE vpn_server_transports SET health_status = 'healthy', last_checked_at = NOW() WHERE server_id = @server`)
	return fixture
}

func (f coreActivationFixture) exec(t *testing.T, sql string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, pgx.NamedArgs{"cluster": f.cluster, "node": f.node, "server": f.server}); err != nil {
		t.Fatal(err)
	}
}

func (f coreActivationFixture) activate(ctx context.Context, cluster, node, server uuid.UUID, protocol string) error {
	conn, err := pgx.ConnectConfig(ctx, f.pool.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `SELECT
		set_config('midorivpn.activation.cluster_id', $1, false),
		set_config('midorivpn.activation.node_id', $2, false),
		set_config('midorivpn.activation.server_id', $3, false),
		set_config('midorivpn.activation.protocol', $4, false),
		set_config('midorivpn.activation.migrator_role', COALESCE(NULLIF($5::text, ''), session_user::text), false)`,
		cluster.String(), node.String(), server.String(), protocol, f.migratorRole); err != nil {
		return err
	}
	_, err = conn.Exec(ctx, f.sql)
	return err
}

func (f coreActivationFixture) snapshot(t *testing.T) string {
	t.Helper()
	var snapshot string
	if err := f.pool.QueryRow(context.Background(), `
		SELECT jsonb_build_array(to_jsonb(cluster), to_jsonb(node), to_jsonb(server))::text
		FROM clusters cluster, core_nodes node, vpn_servers server
		WHERE cluster.id = $1 AND node.id = $2 AND server.id = $3`, f.cluster, f.node, f.server).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestCoreActivationAPIInventoryAndIdempotency(t *testing.T) {
	f := newCoreActivationFixture(t)
	ctx := context.Background()
	fleet := repo.NewMulticlusterRepo(f.pool)
	candidateListed := func() bool {
		recorder := httptest.NewRecorder()
		control.NewHandler(f.pool, &config.Config{}).ListServerCandidates(recorder,
			httptest.NewRequest(http.MethodGet, "/api/v1/control/servers/candidates?protocol=wireguard", nil))
		if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("candidates status=%d cache=%q", recorder.Code, recorder.Header().Get("Cache-Control"))
		}
		for _, candidate := range decodeResponseData[[]models.ServerCandidate](t, recorder) {
			if candidate.ID == f.server {
				return true
			}
		}
		return false
	}
	if candidateListed() {
		t.Fatal("API listed the unbound inactive Core as a candidate")
	}
	eligible, err := fleet.ServerPlacementEligible(ctx, f.server, "wireguard", repo.DefaultNodeFreshness)
	if err != nil || eligible {
		t.Fatalf("unbound API server placement = %t, %v", eligible, err)
	}
	if err := f.activate(ctx, f.cluster, f.node, f.server, "wireguard"); err != nil {
		t.Fatal(err)
	}
	eligible, err = fleet.ServerPlacementEligible(ctx, f.server, "wireguard", repo.DefaultNodeFreshness)
	if err != nil || !eligible {
		t.Fatalf("activated API server placement = %t, %v", eligible, err)
	}
	if !candidateListed() {
		t.Fatal("API did not list the activated Core as a candidate")
	}
	var clusterState, nodeState string
	var boundNode uuid.UUID
	var legacy bool
	if err := f.pool.QueryRow(ctx, `
		SELECT cluster.state, node.state, server.node_id, server.legacy_node_unbound
		FROM clusters cluster, core_nodes node, vpn_servers server
		WHERE cluster.id = $1 AND node.id = $2 AND server.id = $3`, f.cluster, f.node, f.server).
		Scan(&clusterState, &nodeState, &boundNode, &legacy); err != nil {
		t.Fatal(err)
	}
	if clusterState != "active" || nodeState != "active" || boundNode != f.node || legacy {
		t.Fatalf("incorrect activation: %s/%s/%s/legacy=%t", clusterState, nodeState, boundNode, legacy)
	}
	before := f.snapshot(t)
	if err := f.activate(ctx, f.cluster, f.node, f.server, "wireguard"); err != nil {
		t.Fatal(err)
	}
	if after := f.snapshot(t); after != before {
		t.Fatal("repeat activation changed inventory, timestamps or legacy state")
	}
	// The exact binding can be retried while carrying traffic; it must neither
	// reset counters nor treat existing traffic as an initial rebind.
	f.exec(t, `UPDATE vpn_servers SET current_peers = 1 WHERE id = @server`)
	f.exec(t, `UPDATE node_observations SET current_peers = 1 WHERE node_id = @node`)
	before = f.snapshot(t)
	if err := f.activate(ctx, f.cluster, f.node, f.server, "wireguard"); err != nil {
		t.Fatalf("retry with traffic: %v", err)
	}
	if f.snapshot(t) != before {
		t.Fatal("repeat activation changed live counters or inventory")
	}
	f.exec(t, `UPDATE core_nodes SET state = 'revoked' WHERE id = @node`)
	before = f.snapshot(t)
	if err := f.activate(ctx, f.cluster, f.node, f.server, "wireguard"); err == nil {
		t.Fatal("retry revived a revoked node")
	}
	if f.snapshot(t) != before {
		t.Fatal("refused retry changed revoked inventory")
	}
}

func TestCoreActivationRejectsUnsafeStateWithoutPartialWrites(t *testing.T) {
	cases := []struct {
		name string
		sql  []string
	}{
		{"node_not_enrolled", []string{`UPDATE core_nodes SET identity_public_key = NULL, enrolled_at = NULL WHERE id = @node`}},
		{"node_enrolling", []string{`UPDATE core_nodes SET state = 'enrolling' WHERE id = @node`}},
		{"node_revoked", []string{`UPDATE core_nodes SET state = 'revoked' WHERE id = @node`}},
		{"node_retired", []string{`UPDATE core_nodes SET state = 'retired' WHERE id = @node`}},
		{"node_draining", []string{`UPDATE core_nodes SET state = 'draining' WHERE id = @node`}},
		{"cluster_revoked", []string{`UPDATE clusters SET state = 'revoked' WHERE id = @cluster`}},
		{"cluster_retired", []string{`UPDATE clusters SET state = 'retired' WHERE id = @cluster`}},
		{"cluster_draining", []string{`UPDATE clusters SET state = 'draining' WHERE id = @cluster`}},
		{"server_inactive", []string{`UPDATE vpn_servers SET is_active = FALSE WHERE id = @server`}},
		{"server_draining", []string{`UPDATE vpn_servers SET draining_at = NOW() WHERE id = @server`}},
		{"server_invalid_capacity", []string{`UPDATE vpn_servers SET current_peers = -1 WHERE id = @server`}},
		{"legacy_exception", []string{`UPDATE vpn_servers SET legacy_node_unbound = TRUE WHERE id = @server`}},
		{"missing_observation", []string{`DELETE FROM node_observations WHERE node_id = @node`}},
		{"missing_desired", []string{
			`UPDATE node_observations SET applied_revision = NULL WHERE node_id = @node`,
			`DELETE FROM desired_revisions WHERE node_id = @node`,
		}},
		{"unapplied_revision", []string{`UPDATE node_observations SET applied_revision = NULL WHERE node_id = @node`}},
		{"newer_desired_unapplied", []string{`
			INSERT INTO desired_revisions (node_id, revision, previous_revision, schema_version, minimum_core_version,
			    payload, payload_sha256, signature, signing_key_id, issued_at, expires_at)
			SELECT node_id, 2, 1, schema_version, minimum_core_version, payload, payload_sha256, signature, signing_key_id,
			    issued_at, expires_at FROM desired_revisions WHERE node_id = @node`}},
		{"expired_desired", []string{`UPDATE desired_revisions SET issued_at = NOW() - INTERVAL '2 hours', expires_at = NOW() - INTERVAL '1 hour' WHERE node_id = @node`}},
		{"stale_observation", []string{`
			WITH stale AS (UPDATE node_observations SET received_at = NOW() - INTERVAL '91 seconds' WHERE node_id = @node RETURNING received_at)
			UPDATE core_nodes SET created_at = NOW() - INTERVAL '3 minutes', enrolled_at = NOW() - INTERVAL '2 minutes',
			    last_seen_at = stale.received_at FROM stale WHERE id = @node`}},
		{"missing_last_seen", []string{`UPDATE core_nodes SET last_seen_at = NULL WHERE id = @node`}},
		{"future_observation", []string{`
			WITH future AS (UPDATE node_observations SET received_at = NOW() + INTERVAL '1 hour' WHERE node_id = @node RETURNING received_at)
			UPDATE core_nodes SET last_seen_at = future.received_at FROM future WHERE id = @node`}},
		{"observation_predates_enrollment", []string{`UPDATE core_nodes SET enrolled_at = NOW() + INTERVAL '1 hour' WHERE id = @node`}},
		{"unhealthy", []string{`UPDATE node_observations SET health_status = 'degraded' WHERE node_id = @node`}},
		{"latest_observation_unhealthy", []string{`
			WITH latest AS (
			    INSERT INTO node_observations (node_id, applied_revision, core_version, health_status, version_compatible, max_peers, reported_at)
			    VALUES (@node, 1, '2.0.0', 'error', TRUE, 10, NOW()) RETURNING received_at
			) UPDATE core_nodes SET last_seen_at = latest.received_at FROM latest WHERE id = @node`}},
		{"observed_error", []string{`UPDATE node_observations SET last_error_code = 'apply_failed' WHERE node_id = @node`}},
		{"incompatible_version", []string{`UPDATE node_observations SET version_compatible = FALSE WHERE node_id = @node`}},
		{"version_drift", []string{`UPDATE core_nodes SET core_version = '2.0.1' WHERE id = @node`}},
		{"server_capacity_full", []string{`UPDATE vpn_servers SET current_peers = max_peers WHERE id = @server`}},
		{"node_capacity_full", []string{`UPDATE node_observations SET current_peers = max_peers WHERE node_id = @node`}},
		{"unbound_server_in_use", []string{`UPDATE vpn_servers SET current_peers = 1 WHERE id = @server`}},
		{"unbound_node_in_use", []string{`UPDATE node_observations SET current_peers = 1 WHERE node_id = @node`}},
		{"transport_disabled", []string{`UPDATE vpn_server_transports SET enabled = FALSE WHERE server_id = @server`}},
		{"transport_unhealthy", []string{`UPDATE vpn_server_transports SET health_status = 'degraded' WHERE server_id = @server`}},
		{"transport_stale", []string{`UPDATE vpn_server_transports SET last_checked_at = NOW() - INTERVAL '91 seconds' WHERE server_id = @server`}},
		{"transport_absent_from_desired", []string{`UPDATE desired_revisions SET payload = jsonb_set(payload, '{transports}', '[]'::jsonb) WHERE node_id = @node`}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newCoreActivationFixture(t)
			for _, sql := range test.sql {
				f.exec(t, sql)
			}
			before := f.snapshot(t)
			if err := f.activate(context.Background(), f.cluster, f.node, f.server, "wireguard"); err == nil {
				t.Fatal("unsafe activation succeeded")
			}
			if after := f.snapshot(t); after != before {
				t.Fatal("rejected activation partially changed cluster/node/server inventory")
			}
		})
	}
}

func TestCoreActivationRejectsCrossInventoryReassignment(t *testing.T) {
	a, b := newCoreActivationFixture(t), newCoreActivationFixture(t)
	ctx := context.Background()
	beforeA, beforeB := a.snapshot(t), b.snapshot(t)
	if err := a.activate(ctx, a.cluster, b.node, a.server, "wireguard"); err == nil {
		t.Fatal("activation accepted a node from another cluster")
	}
	if a.snapshot(t) != beforeA || b.snapshot(t) != beforeB {
		t.Fatal("cluster mismatch changed inventory")
	}
	if err := a.activate(ctx, a.cluster, a.node, a.server, "wireguard"); err != nil {
		t.Fatal(err)
	}
	beforeA = a.snapshot(t)
	for _, request := range []struct{ cluster, node, server uuid.UUID }{
		{b.cluster, b.node, a.server}, // occupied server cannot move to another node
		{a.cluster, a.node, b.server}, // occupied node cannot take another server
	} {
		if err := a.activate(ctx, request.cluster, request.node, request.server, "wireguard"); err == nil {
			t.Fatal("activation accepted an occupied server or node")
		}
		if a.snapshot(t) != beforeA || b.snapshot(t) != beforeB {
			t.Fatal("reassignment rejection changed inventory")
		}
	}
}

func TestCoreActivationConcurrentRetries(t *testing.T) {
	f := newCoreActivationFixture(t)
	ctx := context.Background()
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- f.activate(ctx, f.cluster, f.node, f.server, "wireguard") }()
	}
	for range 2 {
		err := <-results
		var pgError *pgconn.PgError
		if err != nil && (!errors.As(err, &pgError) || pgError.Code != "40001") {
			t.Fatalf("concurrent activation: %v", err)
		}
	}
	if err := f.activate(ctx, f.cluster, f.node, f.server, "wireguard"); err != nil {
		t.Fatalf("retry after concurrent activation: %v", err)
	}
}

func TestCoreActivationRefusesWrongMigratorIdentity(t *testing.T) {
	f := newCoreActivationFixture(t)
	before := f.snapshot(t)
	f.migratorRole = "not-the-session-identity"
	err := f.activate(context.Background(), f.cluster, f.node, f.server, "wireguard")
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "42501" {
		t.Fatalf("wrong migrator identity error = %v, want insufficient_privilege", err)
	}
	if f.snapshot(t) != before {
		t.Fatal("wrong identity changed inventory")
	}
}

func TestCoreActivationCentralCertificationRemainsAuthoritative(t *testing.T) {
	f := newCoreActivationFixture(t)
	// Deliberately vary stored central inventory/observation independently. This
	// is a database gate test, not an assertion of real transport certification.
	f.exec(t, `UPDATE vpn_server_transports SET protocol = 'openvpn', metadata = '{}'::jsonb WHERE server_id = @server`)
	f.exec(t, `UPDATE desired_revisions SET payload = jsonb_set(payload, '{transports,0,protocol}', '"openvpn"'::jsonb) WHERE node_id = @node`)
	f.exec(t, `UPDATE node_observations SET transport_states = '{"openvpn":{"status":"healthy","certified":true}}'::jsonb WHERE node_id = @node`)
	before := f.snapshot(t)
	if err := f.activate(context.Background(), f.cluster, f.node, f.server, "openvpn"); err == nil {
		t.Fatal("node-reported certification bypassed central inventory")
	}
	if f.snapshot(t) != before {
		t.Fatal("missing central certification partially activated inventory")
	}
	f.exec(t, `UPDATE vpn_server_transports SET metadata = '{"certified":true}'::jsonb WHERE server_id = @server`)
	if err := f.activate(context.Background(), f.cluster, f.node, f.server, "openvpn"); err != nil {
		t.Fatalf("centrally certified inventory rejected: %v", err)
	}
}

func TestCoreActivationDoesNotEnableActiveSibling(t *testing.T) {
	f := newCoreActivationFixture(t)
	sibling := &models.CoreNode{
		ClusterID: f.cluster, Name: "sibling-" + uuid.NewString()[:8], State: models.ClusterStateActive,
		ManagementHost: uuid.NewString() + ".nodes.test.invalid",
	}
	if err := repo.NewMulticlusterRepo(f.pool).CreateNode(context.Background(), sibling); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(), `DELETE FROM core_nodes WHERE id = $1`, sibling.ID); err != nil {
			t.Error(err)
		}
	})
	before := f.snapshot(t)
	if err := f.activate(context.Background(), f.cluster, f.node, f.server, "wireguard"); err == nil {
		t.Fatal("cluster activation would enable another active node")
	}
	if f.snapshot(t) != before {
		t.Fatal("sibling rejection partially activated inventory")
	}
}

func TestCoreActivationRefusesLiveIntentWithZeroPeerCounter(t *testing.T) {
	for _, kind := range []string{"peer", "operation", "certificate"} {
		t.Run(kind, func(t *testing.T) {
			f := newCoreActivationFixture(t)
			ctx := context.Background()
			user := insertUser(t, f.pool)
			var device uuid.UUID
			if err := f.pool.QueryRow(ctx, `INSERT INTO devices (user_id, reported_name, device_type)
				VALUES ($1, 'activation-test', 'manual') RETURNING id`, user.ID).Scan(&device); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				for _, table := range []string{"peer_operations", "peers", "device_certificates", "devices"} {
					if _, err := f.pool.Exec(ctx, "DELETE FROM "+table+" WHERE user_id = $1", user.ID); err != nil {
						t.Error(err)
					}
				}
			})
			var sql string
			switch kind {
			case "peer":
				sql = `INSERT INTO peers (user_id, device_id, server_id, public_key, assigned_ip)
					VALUES (@user, @device, @server, @key, '10.89.0.2/32')`
			case "operation":
				sql = `INSERT INTO peer_operations (id, action, state, user_id, device_id, server_id, public_key)
					VALUES (gen_random_uuid(), 'connect', 'pending', @user, @device, @server, @key)`
			case "certificate":
				sql = `INSERT INTO device_certificates (id, user_id, device_id, server_id, device_name, serial_number,
					certificate_pem, public_key_sha256, not_before, not_after)
					VALUES (gen_random_uuid(), @user, @device, @server, 'activation-test', @serial, 'TEST', repeat('a',64), NOW(), NOW() + INTERVAL '1 day')`
			}
			if _, err := f.pool.Exec(ctx, sql, pgx.NamedArgs{
				"user": user.ID, "device": device, "server": f.server,
				"key": base64.StdEncoding.EncodeToString(make([]byte, 32)), "serial": uuid.NewString(),
			}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t)
			if err := f.activate(ctx, f.cluster, f.node, f.server, "wireguard"); err == nil {
				t.Fatal("initial binding ignored live intent with a zero server counter")
			}
			if f.snapshot(t) != before {
				t.Fatal("live intent rejection partially activated inventory")
			}
		})
	}
}

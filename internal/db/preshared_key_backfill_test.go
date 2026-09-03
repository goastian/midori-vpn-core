package db_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/goastian/midori-vpn-core/internal/db"
)

func TestBackfillPresharedKeysEncryptsEveryLegacyStoreAndIsResumable(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}
	if err := db.RunMigrations(dsn); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	userID := uuid.New()
	serverID := uuid.New()
	deviceID := uuid.New()
	peerID := uuid.New()
	operationID := uuid.New()
	meshID := uuid.New()
	memberID := uuid.New()
	seed := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users (id, authentik_uid, email) VALUES ($1, $2, 'backfill@test.invalid')`, []any{userID, uuid.NewString()}},
		{`INSERT INTO vpn_servers (id, name, host) VALUES ($1, $2, 'backfill.test.invalid')`, []any{serverID, "Backfill " + uuid.NewString()}},
		{`INSERT INTO devices (id, user_id, reported_name, device_type) VALUES ($1, $2, 'backfill-host', 'manual')`, []any{deviceID, userID}},
		{`INSERT INTO peers (id, user_id, server_id, public_key, preshared_key, assigned_ip, device_id)
		  VALUES ($1, $2, $3, $4, 'peer-legacy-secret', $5, $6)`, []any{peerID, userID, serverID, testWireGuardKey(1), "10.253.0.2/32", deviceID}},
		{`INSERT INTO peer_operations
			(id, action, state, user_id, device_id, server_id, public_key, preshared_key)
		  VALUES ($1, 'connect', 'failed', $2, $3, $4, $5, 'operation-legacy-secret')`, []any{operationID, userID, deviceID, serverID, testWireGuardKey(2)}},
		{`INSERT INTO mesh_networks (id, name, subnet, owner_id, invite_code)
		  VALUES ($1, 'Backfill mesh', $2, $3, $4)`, []any{meshID, "10.254.253.0/24", userID, uuid.NewString()}},
		{`INSERT INTO mesh_members (id, mesh_id, user_id, preshared_key, mesh_ip)
		  VALUES ($1, $2, $3, 'mesh-legacy-secret', $4)`, []any{memberID, meshID, userID, "10.254.253.2"}},
	}
	for _, statement := range seed {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed legacy PSKs: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id = $1`, serverID)
	})

	cipher, err := dataencryption.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("dataencryption.New: %v", err)
	}
	report, err := db.BackfillPresharedKeys(ctx, pool, cipher)
	if err != nil {
		t.Fatalf("BackfillPresharedKeys: %v", err)
	}
	if report.Peers != 1 || report.PeerOperations != 1 || report.MeshMembers != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}

	assertEncryptedPSK(t, pool, cipher, "peers", dataencryption.PeerPresharedKey, peerID, "peer-legacy-secret")
	assertEncryptedPSK(t, pool, cipher, "peer_operations", dataencryption.PeerOperationPresharedKey, operationID, "operation-legacy-secret")
	assertEncryptedPSK(t, pool, cipher, "mesh_members", dataencryption.MeshMemberPresharedKey, memberID, "mesh-legacy-secret")

	repeated, err := db.BackfillPresharedKeys(ctx, pool, cipher)
	if err != nil {
		t.Fatalf("repeated BackfillPresharedKeys: %v", err)
	}
	if repeated != (db.PresharedKeyBackfillReport{}) {
		t.Fatalf("repeated backfill changed rows: %+v", repeated)
	}
}

func assertEncryptedPSK(t *testing.T, pool *pgxpool.Pool, cipher *dataencryption.Cipher, table string, scope dataencryption.Scope, id uuid.UUID, expected string) {
	t.Helper()
	var legacy string
	var ciphertext []byte
	var version int16
	query := `SELECT preshared_key, preshared_key_ciphertext, preshared_key_version FROM ` + table + ` WHERE id = $1`
	if err := pool.QueryRow(context.Background(), query, id).Scan(&legacy, &ciphertext, &version); err != nil {
		t.Fatalf("load encrypted %s PSK: %v", table, err)
	}
	if legacy != "" || len(ciphertext) == 0 || version != dataencryption.CurrentVersion {
		t.Fatalf("%s retained plaintext or omitted versioned ciphertext", table)
	}
	plaintext, err := cipher.OpenPresharedKey(scope, id, version, ciphertext)
	if err != nil || plaintext != expected {
		t.Fatalf("decrypt %s PSK: plaintext=%q err=%v", table, plaintext, err)
	}
}

func testWireGuardKey(fill byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 44)
	for index := range result[:43] {
		result[index] = alphabet[int(fill+byte(index))%len(alphabet)]
	}
	result[43] = '='
	return string(result)
}

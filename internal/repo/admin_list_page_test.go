package repo_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/repo"
)

func TestAdminListPagesFilterCountAndBoundResults(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := uuid.NewString()
	activeUID := "ctl05-active-" + suffix
	bannedUID := "ctl05-banned-" + suffix
	activeEmail := activeUID + "@test.invalid"
	bannedEmail := bannedUID + "@test.invalid"

	var activeUserID, bannedUserID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (authentik_uid, email, display_name)
		VALUES ($1, $2, 'Alpha'), ($3, $4, 'Beta')
		RETURNING id`, activeUID, activeEmail, bannedUID, bannedEmail).Scan(&activeUserID); err != nil {
		t.Fatalf("insert active user: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE authentik_uid = $1`, bannedUID).Scan(&bannedUserID); err != nil {
		t.Fatalf("load banned user: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET is_banned = TRUE WHERE id = $1`, bannedUserID); err != nil {
		t.Fatalf("ban fixture user: %v", err)
	}

	var serverID uuid.UUID
	serverName := "ctl05-server-" + suffix
	if err := pool.QueryRow(ctx, `
		INSERT INTO vpn_servers (name, host, public_key, location, country_code)
		VALUES ($1, $2, 'test-key', 'Santo Domingo', 'DO') RETURNING id`,
		serverName, serverName+".test.invalid").Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}

	var deviceID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (user_id, client_instance_id, reported_name, device_type)
		VALUES ($1, $2, $3, 'desktop') RETURNING id`, activeUserID, uuid.New(), "ctl05-device-"+suffix).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO peers (user_id, server_id, public_key, assigned_ip, is_active, device_name, device_id)
		VALUES ($1, $2, $3, '10.77.0.2/32', TRUE, $4, $5),
		       ($1, $2, $6, '10.77.0.3/32', FALSE, $4, $5)`,
		activeUserID, serverID, "active-"+suffix, "ctl05-device-"+suffix, deviceID, "inactive-"+suffix); err != nil {
		t.Fatalf("insert peers: %v", err)
	}
	action := "ctl05.test." + suffix
	if _, err := pool.Exec(ctx, `INSERT INTO audit_logs (user_id, action) VALUES ($1, $2)`, activeUserID, action); err != nil {
		t.Fatalf("insert audit log: %v", err)
	}
	origin := "moz-extension://ctl05-" + suffix
	if _, err := pool.Exec(ctx, `INSERT INTO trusted_extension_origins (origin) VALUES ($1)`, origin); err != nil {
		t.Fatalf("insert extension origin: %v", err)
	}
	meshName := "ctl05-mesh-" + suffix
	var meshID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO mesh_networks (name, subnet, owner_id, invite_code, is_session, country_code)
		VALUES ($1, '10.199.0.0/24', $2, $3, TRUE, 'DO') RETURNING id`, meshName, activeUserID, uuid.NewString()).Scan(&meshID); err != nil {
		t.Fatalf("insert mesh: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_logs WHERE action = $1`, action)
		_, _ = pool.Exec(context.Background(), `DELETE FROM trusted_extension_origins WHERE origin = $1`, origin)
		_, _ = pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id = $1`, serverID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{activeUserID, bannedUserID})
	})

	users, total, err := repo.NewUserRepo(pool).ListAdminPage(ctx, repo.ListOptions{
		Limit: 1, Offset: 1, Search: "ctl05-", Status: "all", Sort: "email", Order: "asc",
	})
	if err != nil || total < 2 || len(users) != 1 {
		t.Fatalf("user page: total=%d len=%d err=%v", total, len(users), err)
	}

	servers, total, err := repo.NewServerRepo(pool).ListAdminPage(ctx, repo.ListOptions{
		Limit: 10, Search: serverName, Status: "active", Sort: "name", Order: "asc",
	})
	if err != nil || total != 1 || len(servers) != 1 || servers[0].ID != serverID {
		t.Fatalf("server page: total=%d servers=%+v err=%v", total, servers, err)
	}

	peerRepo := repo.NewPeerRepo(pool)
	peers, total, err := peerRepo.ListAdminPage(ctx, repo.AdminPeerListOptions{ListOptions: repo.ListOptions{
		Limit: 10, Search: "ctl05-device-", Status: "all", Sort: "created_at", Order: "desc",
	}})
	if err != nil || total != 2 || len(peers) != 2 {
		t.Fatalf("peer page: total=%d len=%d err=%v", total, len(peers), err)
	}
	peers, total, err = peerRepo.ListDevicePage(ctx, repo.DeviceSessionListOptions{
		ListOptions: repo.ListOptions{Limit: 10, Status: "active", Sort: "traffic", Order: "desc"},
		UserID:      activeUserID, DeviceID: deviceID,
	})
	if err != nil || total != 1 || len(peers) != 1 || !peers[0].IsActive {
		t.Fatalf("device session page: total=%d peers=%+v err=%v", total, peers, err)
	}

	logs, total, err := repo.NewAuditRepo(pool).ListAdminPage(ctx, repo.AdminAuditListOptions{
		ListOptions: repo.ListOptions{Limit: 10, Search: activeEmail, Status: "all", Sort: "action", Order: "asc"},
		Action:      action,
	})
	if err != nil || total != 1 || len(logs) != 1 || logs[0].Action != action {
		t.Fatalf("audit page: total=%d logs=%+v err=%v", total, logs, err)
	}

	origins, total, err := repo.NewTrustedExtensionRepo(pool).ListAdminPage(ctx, repo.ListOptions{
		Limit: 10, Search: origin, Status: "trusted", Sort: "origin", Order: "asc",
	})
	if err != nil || total != 1 || len(origins) != 1 || origins[0].Origin != origin {
		t.Fatalf("extension origin page: total=%d origins=%+v err=%v", total, origins, err)
	}

	meshes, total, err := repo.NewMeshRepo(pool).ListAdminPage(ctx, repo.ListOptions{
		Limit: 10, Search: meshName, Status: "active", Sort: "member_count", Order: "asc",
	})
	if err != nil || total != 1 || len(meshes) != 1 || meshes[0].ID != meshID {
		t.Fatalf("mesh page: total=%d meshes=%+v err=%v", total, meshes, err)
	}
}

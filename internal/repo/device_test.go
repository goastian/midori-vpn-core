package repo_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

func insertDeviceTestServer(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO vpn_servers (name, host, legacy_node_unbound)
		VALUES ($1, $2, TRUE)
		RETURNING id`, "Device Test Server "+uuid.NewString(), "device.test.invalid").Scan(&id); err != nil {
		t.Fatalf("insert device test server: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id = $1`, id)
	})
	return id
}

func insertDeviceTestPeer(t *testing.T, pool *pgxpool.Pool, userID, serverID, deviceID uuid.UUID, name, ip string, active bool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO peers (user_id, server_id, public_key, assigned_ip, device_name, device_id, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`, userID, serverID, uuid.NewString(), ip, name, deviceID, active).Scan(&id); err != nil {
		t.Fatalf("insert device test peer: %v", err)
	}
	return id
}

func TestDeviceRepoRegisteredIdentityPersistsAndPreservesAlias(t *testing.T) {
	pool := testPool(t)
	deviceRepo := repo.NewDeviceRepo(pool)
	userID := insertTestUser(t, pool)
	clientID := uuid.New()
	firstReference := "net-v1:" + strings.Repeat("A", 43)

	first, err := deviceRepo.ResolveRegistered(context.Background(), userID, clientID, "Old-Host", models.DeviceTypeDesktop, firstReference)
	if err != nil {
		t.Fatalf("ResolveRegistered first call: %v", err)
	}
	if first.ClientInstanceID == nil || *first.ClientInstanceID != clientID || first.DisplayName != "Old-Host" {
		t.Fatalf("unexpected first device: %#v", first)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE devices SET alias = 'Work laptop' WHERE id = $1`, first.ID); err != nil {
		t.Fatalf("set alias: %v", err)
	}

	secondReference := "net-v1:" + strings.Repeat("B", 43)
	second, err := deviceRepo.ResolveRegistered(context.Background(), userID, clientID, "New-Host", models.DeviceTypeDesktop, secondReference)
	if err != nil {
		t.Fatalf("ResolveRegistered second call: %v", err)
	}
	if second.ID != first.ID || second.ReportedName != "New-Host" || second.Alias != "Work laptop" || second.DisplayName != "Work laptop" {
		t.Fatalf("stable device update mismatch: first=%#v second=%#v", first, second)
	}
	if second.AdapterReference != secondReference {
		t.Fatalf("adapter reference = %q, want %q", second.AdapterReference, secondReference)
	}
	observedAt := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	if err := deviceRepo.TouchLastSeen(context.Background(), second.ID, observedAt); err != nil {
		t.Fatalf("TouchLastSeen: %v", err)
	}
	var lastSeen time.Time
	if err := pool.QueryRow(context.Background(), `SELECT last_seen_at FROM devices WHERE id = $1`, second.ID).Scan(&lastSeen); err != nil {
		t.Fatalf("read last_seen_at: %v", err)
	}
	if lastSeen.Before(observedAt) {
		t.Fatalf("last_seen_at = %s, want at least %s", lastSeen, observedAt)
	}
}

func TestDeviceRepoAdoptsOnlyOneUnambiguousLegacyDevice(t *testing.T) {
	pool := testPool(t)
	deviceRepo := repo.NewDeviceRepo(pool)
	userID := insertTestUser(t, pool)
	serverID := insertDeviceTestServer(t, pool)
	legacy, err := deviceRepo.CreateLegacy(context.Background(), userID, "shared-host")
	if err != nil {
		t.Fatal(err)
	}
	insertDeviceTestPeer(t, pool, userID, serverID, legacy.ID, "shared-host", "10.99.1.2/32", true)

	clientID := uuid.New()
	adopted, err := deviceRepo.ResolveRegistered(context.Background(), userID, clientID, "shared-host", models.DeviceTypeDesktop, "")
	if err != nil {
		t.Fatalf("adopt sole legacy device: %v", err)
	}
	if adopted.ID != legacy.ID || adopted.ClientInstanceID == nil || *adopted.ClientInstanceID != clientID {
		t.Fatalf("legacy device was not adopted: legacy=%#v adopted=%#v", legacy, adopted)
	}
}

func TestDeviceRepoDoesNotMergeAmbiguousLegacyDevices(t *testing.T) {
	pool := testPool(t)
	deviceRepo := repo.NewDeviceRepo(pool)
	userID := insertTestUser(t, pool)
	serverID := insertDeviceTestServer(t, pool)
	first, err := deviceRepo.CreateLegacy(context.Background(), userID, "same-host")
	if err != nil {
		t.Fatal(err)
	}
	second, err := deviceRepo.CreateLegacy(context.Background(), userID, "same-host")
	if err != nil {
		t.Fatal(err)
	}
	insertDeviceTestPeer(t, pool, userID, serverID, first.ID, "same-host", "10.99.2.2/32", true)
	insertDeviceTestPeer(t, pool, userID, serverID, second.ID, "same-host", "10.99.2.3/32", true)

	registered, err := deviceRepo.ResolveRegistered(context.Background(), userID, uuid.New(), "same-host", models.DeviceTypeDesktop, "")
	if err != nil {
		t.Fatalf("create registered device beside ambiguous legacy devices: %v", err)
	}
	if registered.ID == first.ID || registered.ID == second.ID {
		t.Fatalf("ambiguous legacy identity was merged: %#v", registered)
	}
}

func TestDeviceRepoRejectsRevokedRegisteredIdentity(t *testing.T) {
	pool := testPool(t)
	deviceRepo := repo.NewDeviceRepo(pool)
	userID := insertTestUser(t, pool)
	clientID := uuid.New()
	device, err := deviceRepo.ResolveRegistered(context.Background(), userID, clientID, "revoked-host", models.DeviceTypeDesktop, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE devices SET revoked_at = NOW() WHERE id = $1`, device.ID); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	if _, err := deviceRepo.ResolveRegistered(context.Background(), userID, clientID, "revoked-host", models.DeviceTypeDesktop, ""); !errors.Is(err, repo.ErrDeviceRevoked) {
		t.Fatalf("ResolveRegistered revoked error = %v, want %v", err, repo.ErrDeviceRevoked)
	}
}

func TestDeviceRepoCountsDevicesWithActiveSessionsByExplicitType(t *testing.T) {
	pool := testPool(t)
	deviceRepo := repo.NewDeviceRepo(pool)
	userID := insertTestUser(t, pool)
	serverID := insertDeviceTestServer(t, pool)
	desktop, err := deviceRepo.ResolveRegistered(context.Background(), userID, uuid.New(), "browser-looking-name", models.DeviceTypeDesktop, "")
	if err != nil {
		t.Fatal(err)
	}
	manual, err := deviceRepo.CreateLegacy(context.Background(), userID, "desktop-looking-name")
	if err != nil {
		t.Fatal(err)
	}
	mobile, err := deviceRepo.ResolveRegistered(context.Background(), userID, uuid.New(), "phone", models.DeviceTypeMobile, "")
	if err != nil {
		t.Fatal(err)
	}
	insertDeviceTestPeer(t, pool, userID, serverID, desktop.ID, desktop.ReportedName, "10.99.3.2/32", true)
	insertDeviceTestPeer(t, pool, userID, serverID, manual.ID, manual.ReportedName, "10.99.3.3/32", true)
	insertDeviceTestPeer(t, pool, userID, serverID, mobile.ID, mobile.ReportedName, "10.99.3.4/32", false)

	usage, err := deviceRepo.ActiveUsageByUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if usage[models.DeviceTypeDesktop] != 1 || usage[models.DeviceTypeManual] != 1 || usage[models.DeviceTypeMobile] != 0 {
		t.Fatalf("unexpected active device usage: %#v", usage)
	}
}

func TestDeviceCertificateRepoUsesDeviceIdentityInsteadOfName(t *testing.T) {
	pool := testPool(t)
	deviceRepo := repo.NewDeviceRepo(pool)
	certificateRepo := repo.NewDeviceCertificateRepo(pool)
	userID := insertTestUser(t, pool)
	serverID := insertDeviceTestServer(t, pool)
	sharedReference := "net-v1:" + strings.Repeat("C", 43)
	first, err := deviceRepo.ResolveRegistered(context.Background(), userID, uuid.New(), "same-host", models.DeviceTypeDesktop, sharedReference)
	if err != nil {
		t.Fatal(err)
	}
	second, err := deviceRepo.ResolveRegistered(context.Background(), userID, uuid.New(), "same-host", models.DeviceTypeDesktop, sharedReference)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("same hostname and adapter reference merged distinct installation identities")
	}

	newCertificate := func(deviceID uuid.UUID, serial string) *models.DeviceCertificate {
		now := time.Now().UTC()
		return &models.DeviceCertificate{
			ID: uuid.New(), UserID: userID, ServerID: serverID, DeviceID: &deviceID,
			DeviceName: "same-host", SerialNumber: serial, CertificatePEM: "CERTIFICATE",
			PublicKeySHA256: strings.Repeat("a", 64), NotBefore: now, NotAfter: now.Add(time.Hour),
		}
	}
	if err := certificateRepo.ReplaceActive(context.Background(), newCertificate(first.ID, uuid.NewString())); err != nil {
		t.Fatalf("insert first same-name certificate: %v", err)
	}
	if err := certificateRepo.ReplaceActive(context.Background(), newCertificate(second.ID, uuid.NewString())); err != nil {
		t.Fatalf("insert second same-name certificate: %v", err)
	}
	if err := certificateRepo.ReplaceActive(context.Background(), newCertificate(first.ID, uuid.NewString())); err != nil {
		t.Fatalf("replace first device certificate: %v", err)
	}

	certificates, err := certificateRepo.ListByUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	activeByDevice := map[uuid.UUID]int{}
	for _, certificate := range certificates {
		if certificate.RevokedAt == nil && certificate.DeviceID != nil {
			activeByDevice[*certificate.DeviceID]++
		}
	}
	if activeByDevice[first.ID] != 1 || activeByDevice[second.ID] != 1 {
		t.Fatalf("certificate identity mismatch: %#v", activeByDevice)
	}
}

func TestDeviceCertificateRepoRejectsMissingDeviceID(t *testing.T) {
	repository := repo.NewDeviceCertificateRepo(nil)
	if err := repository.ReplaceActive(context.Background(), &models.DeviceCertificate{}); err == nil {
		t.Fatal("certificate without device_id was accepted")
	}
}

func TestDeviceRepoListsAliasesAndPaginatesSessionHistory(t *testing.T) {
	pool := testPool(t)
	deviceRepo := repo.NewDeviceRepo(pool)
	peerRepo := repo.NewPeerRepo(pool)
	userID := insertTestUser(t, pool)
	serverID := insertDeviceTestServer(t, pool)
	device, err := deviceRepo.ResolveRegistered(context.Background(), userID, uuid.New(), "history-host", models.DeviceTypeDesktop, "")
	if err != nil {
		t.Fatal(err)
	}
	olderID := insertDeviceTestPeer(t, pool, userID, serverID, device.ID, "history-host", "10.99.4.2/32", false)
	newerID := insertDeviceTestPeer(t, pool, userID, serverID, device.ID, "history-host", "10.99.4.3/32", true)
	if _, err := pool.Exec(context.Background(), `
		UPDATE peers SET created_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, olderID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE peers SET created_at = NOW() WHERE id = $1`, newerID); err != nil {
		t.Fatal(err)
	}

	updated, err := deviceRepo.UpdateAlias(context.Background(), userID, device.ID, "Private laptop")
	if err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != "Private laptop" {
		t.Fatalf("display name = %q", updated.DisplayName)
	}
	devices, err := deviceRepo.ListByUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].ID != device.ID || devices[0].Alias != "Private laptop" {
		t.Fatalf("unexpected device list: %#v", devices)
	}
	active, err := peerRepo.ListActiveByUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].ID != newerID {
		t.Fatalf("active sessions = %#v", active)
	}
	firstPage, err := peerRepo.ListByDevice(context.Background(), userID, device.ID, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	secondPage, err := peerRepo.ListByDevice(context.Background(), userID, device.ID, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	total, err := peerRepo.CountByDevice(context.Background(), userID, device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(firstPage) != 1 || firstPage[0].ID != newerID || len(secondPage) != 1 || secondPage[0].ID != olderID {
		t.Fatalf("unexpected history total=%d first=%#v second=%#v", total, firstPage, secondPage)
	}
}

func TestDeviceRepoRevocationBlocksAccessWithoutHidingPendingSession(t *testing.T) {
	pool := testPool(t)
	deviceRepo := repo.NewDeviceRepo(pool)
	userID := insertTestUser(t, pool)
	serverID := insertDeviceTestServer(t, pool)
	device, err := deviceRepo.ResolveRegistered(context.Background(), userID, uuid.New(), "revoke-host", models.DeviceTypeDesktop, "")
	if err != nil {
		t.Fatal(err)
	}
	peerID := insertDeviceTestPeer(t, pool, userID, serverID, device.ID, "revoke-host", "10.99.5.2/32", true)
	cipher, _ := dataencryption.New([]byte("0123456789abcdef0123456789abcdef"))
	ciphertext, version, err := cipher.SealPresharedKey(dataencryption.PeerPresharedKey, peerID, "recoverable-test-value")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE peers SET preshared_key_ciphertext = $2, preshared_key_version = $3 WHERE id = $1`, peerID, ciphertext, version); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE vpn_servers SET current_peers = 1 WHERE id = $1`, serverID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO device_certificates (
			id, user_id, server_id, device_name, device_id, serial_number,
			certificate_pem, public_key_sha256, not_before, not_after
		) VALUES ($1, $2, $3, $4, $5, $6, 'CERTIFICATE', $7, $8, $9)`,
		uuid.New(), userID, serverID, device.ReportedName, device.ID, uuid.NewString(), strings.Repeat("f", 64), now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	revoked, err := deviceRepo.RevokeForCleanup(context.Background(), userID, device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("device was not revoked")
	}
	var active bool
	var psk string
	var storedCiphertext []byte
	var storedVersion *int16
	if err := pool.QueryRow(context.Background(), `
		SELECT is_active, preshared_key, preshared_key_ciphertext, preshared_key_version
		FROM peers WHERE id = $1`, peerID).Scan(&active, &psk, &storedCiphertext, &storedVersion); err != nil {
		t.Fatal(err)
	}
	if !active || psk != "" || storedCiphertext != nil || storedVersion != nil {
		t.Fatalf("peer material remains: active=%v plaintext=%q ciphertext_bytes=%d version=%v", active, psk, len(storedCiphertext), storedVersion)
	}
	var certificateRevoked bool
	if err := pool.QueryRow(context.Background(), `
		SELECT revoked_at IS NOT NULL AND revocation_reason = 'device-revoked'
		FROM device_certificates WHERE device_id = $1`, device.ID).Scan(&certificateRevoked); err != nil {
		t.Fatal(err)
	}
	var currentPeers int
	if err := pool.QueryRow(context.Background(), `SELECT current_peers FROM vpn_servers WHERE id = $1`, serverID).Scan(&currentPeers); err != nil {
		t.Fatal(err)
	}
	if !certificateRevoked || currentPeers != 1 {
		t.Fatalf("revocation mismatch: certificate=%v current_peers=%d", certificateRevoked, currentPeers)
	}
	count, err := repo.NewPeerRepo(pool).CountByDevice(context.Background(), userID, device.ID)
	if err != nil || count != 1 {
		t.Fatalf("history count=%d err=%v", count, err)
	}
}

package repo_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

func insertDeviceTestServer(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO vpn_servers (name, host)
		VALUES ($1, $2)
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
	first, err := deviceRepo.ResolveRegistered(context.Background(), userID, uuid.New(), "same-host", models.DeviceTypeDesktop, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := deviceRepo.ResolveRegistered(context.Background(), userID, uuid.New(), "same-host", models.DeviceTypeDesktop, "")
	if err != nil {
		t.Fatal(err)
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

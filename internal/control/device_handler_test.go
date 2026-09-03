package control

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/models"
)

func TestAdapterLabelUsesOnlyShortPrivateReference(t *testing.T) {
	raw := make([]byte, 32)
	copy(raw, []byte{0x7f, 0x3a, 0x91, 0xc2})
	reference := "net-v1:" + base64.RawURLEncoding.EncodeToString(raw)
	if got := adapterLabel(reference); got != "LAN · 7F3A91C2" {
		t.Fatalf("adapterLabel() = %q", got)
	}
	for _, invalid := range []string{"", "02:11:22:33:44:55", "net-v1:short"} {
		if got := adapterLabel(invalid); got != "" {
			t.Fatalf("adapterLabel(%q) = %q", invalid, got)
		}
	}
}

func TestPresentDeviceSeparatesStableIdentityAndActiveSession(t *testing.T) {
	now := time.Now().UTC()
	deviceID := uuid.New()
	device := models.Device{
		ID: deviceID, ReportedName: "host", Alias: "Work laptop", DisplayName: "Work laptop",
		DeviceType: models.DeviceTypeDesktop, FirstSeenAt: now, LastSeenAt: now,
	}
	peer := &models.Peer{ID: uuid.New(), DeviceID: &deviceID, ServerID: uuid.New(), IsActive: true, CreatedAt: now}
	presented := presentDevice(device, peer)
	if presented.ID != deviceID || presented.DisplayName != "Work laptop" || presented.Status != "connected" {
		t.Fatalf("unexpected device response: %#v", presented)
	}
	if presented.ActiveConnection == nil || presented.ActiveConnection.ID != peer.ID || presented.ActiveConnection.Protocol != "wireguard" {
		t.Fatalf("unexpected active connection: %#v", presented.ActiveConnection)
	}
	device.RevokedAt = &now
	presented = presentDevice(device, peer)
	if presented.Status != "cleanup_pending" {
		t.Fatalf("revoked status = %q", presented.Status)
	}
	presented = presentDevice(device, nil)
	if presented.Status != "revoked" {
		t.Fatalf("converged revoked status = %q", presented.Status)
	}
}

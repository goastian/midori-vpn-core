package control

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/models"
)

func TestNormalizeDeviceRequestUsesExplicitIdentity(t *testing.T) {
	clientID := uuid.New()
	reference := "net-v1:" + strings.Repeat("A", 43)
	request, err := normalizeDeviceRequest(&DeviceRequest{
		ClientInstanceID: clientID.String(),
		ReportedName:     "Tecno-09",
		DeviceType:       models.DeviceTypeDesktop,
		AdapterReference: reference,
	}, "ignored-legacy-name")
	if err != nil {
		t.Fatal(err)
	}
	if request.clientInstanceID == nil || *request.clientInstanceID != clientID || request.reportedName != "Tecno-09" || request.deviceType != models.DeviceTypeDesktop || request.adapterReference != reference {
		t.Fatalf("normalized request mismatch: %#v", request)
	}
}

func TestNormalizeLegacyDeviceDoesNotInferTypeFromName(t *testing.T) {
	request, err := normalizeDeviceRequest(nil, "desktop-browser-linux")
	if err != nil {
		t.Fatal(err)
	}
	if request.clientInstanceID != nil || request.deviceType != models.DeviceTypeManual || request.reportedName != "desktop-browser-linux" {
		t.Fatalf("legacy request mismatch: %#v", request)
	}
}

func TestNormalizeDeviceRequestRejectsInvalidIdentity(t *testing.T) {
	validID := uuid.NewString()
	tests := []struct {
		name    string
		request DeviceRequest
	}{
		{name: "missing UUID", request: DeviceRequest{ReportedName: "host", DeviceType: models.DeviceTypeDesktop}},
		{name: "nil UUID", request: DeviceRequest{ClientInstanceID: uuid.Nil.String(), ReportedName: "host", DeviceType: models.DeviceTypeDesktop}},
		{name: "missing name", request: DeviceRequest{ClientInstanceID: validID, DeviceType: models.DeviceTypeDesktop}},
		{name: "unknown type", request: DeviceRequest{ClientInstanceID: validID, ReportedName: "host", DeviceType: "legacy"}},
		{name: "raw MAC", request: DeviceRequest{ClientInstanceID: validID, ReportedName: "host", DeviceType: models.DeviceTypeDesktop, AdapterReference: "02:11:22:33:44:55"}},
		{name: "short reference", request: DeviceRequest{ClientInstanceID: validID, ReportedName: "host", DeviceType: models.DeviceTypeDesktop, AdapterReference: "net-v1:short"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeDeviceRequest(&test.request, ""); err == nil {
				t.Fatal("invalid device identity was accepted")
			}
		})
	}
	if _, err := normalizeDeviceRequest(nil, ""); err == nil {
		t.Fatal("missing device and legacy device_name was accepted")
	}
}

func TestAllPersistedDeviceTypesAreExplicit(t *testing.T) {
	for _, deviceType := range []models.DeviceType{
		models.DeviceTypeDesktop,
		models.DeviceTypeExtension,
		models.DeviceTypeManual,
		models.DeviceTypeMobile,
	} {
		if !deviceType.Valid() {
			t.Fatalf("declared device type %q is invalid", deviceType)
		}
	}
	if models.DeviceType("legacy").Valid() {
		t.Fatal("legacy identity status must not become an inferred device type")
	}
}

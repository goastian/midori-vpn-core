package control

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

var adapterReferenceRe = regexp.MustCompile(`^net-v1:[A-Za-z0-9_-]{43}$`)

type DeviceRequest struct {
	ClientInstanceID string            `json:"client_instance_id"`
	ReportedName     string            `json:"reported_name"`
	DeviceType       models.DeviceType `json:"device_type"`
	AdapterReference string            `json:"adapter_reference,omitempty"`
}

type normalizedDeviceRequest struct {
	clientInstanceID *uuid.UUID
	reportedName     string
	deviceType       models.DeviceType
	adapterReference string
}

func normalizeDeviceRequest(device *DeviceRequest, legacyDeviceName string) (normalizedDeviceRequest, error) {
	if device == nil {
		if strings.TrimSpace(legacyDeviceName) == "" {
			return normalizedDeviceRequest{}, errors.New("device or device_name is required")
		}
		return normalizedDeviceRequest{
			reportedName: sanitizeDeviceName(strings.TrimSpace(legacyDeviceName)),
			deviceType:   models.DeviceTypeManual,
		}, nil
	}

	clientInstanceID, err := uuid.Parse(strings.TrimSpace(device.ClientInstanceID))
	if err != nil || clientInstanceID == uuid.Nil {
		return normalizedDeviceRequest{}, errors.New("device.client_instance_id must be a valid UUID")
	}
	reportedName := sanitizeDeviceName(strings.TrimSpace(device.ReportedName))
	if strings.TrimSpace(device.ReportedName) == "" {
		return normalizedDeviceRequest{}, errors.New("device.reported_name is required")
	}
	if !device.DeviceType.Valid() {
		return normalizedDeviceRequest{}, errors.New("device.device_type is invalid")
	}
	adapterReference := strings.TrimSpace(device.AdapterReference)
	if adapterReference != "" && !adapterReferenceRe.MatchString(adapterReference) {
		return normalizedDeviceRequest{}, errors.New("device.adapter_reference is invalid")
	}

	return normalizedDeviceRequest{
		clientInstanceID: &clientInstanceID,
		reportedName:     reportedName,
		deviceType:       device.DeviceType,
		adapterReference: adapterReference,
	}, nil
}

func (h *Handler) resolveRegisteredDevice(ctx context.Context, userID uuid.UUID, request normalizedDeviceRequest) (*models.Device, error) {
	if request.clientInstanceID == nil {
		return nil, errors.New("registered device identity is missing")
	}
	return h.deviceRepo.ResolveRegistered(
		ctx,
		userID,
		*request.clientInstanceID,
		request.reportedName,
		request.deviceType,
		request.adapterReference,
	)
}

func (h *Handler) resolveCertificateDevice(
	ctx context.Context,
	userID, serverID uuid.UUID,
	request normalizedDeviceRequest,
) (*models.Device, error) {
	if request.clientInstanceID != nil {
		return h.resolveRegisteredDevice(ctx, userID, request)
	}
	device, err := h.deviceRepo.FindSoleLegacyForCertificate(ctx, userID, serverID, request.reportedName)
	if err == nil {
		return device, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, repo.ErrAmbiguousDevice) {
		return nil, err
	}
	return h.deviceRepo.CreateLegacy(ctx, userID, request.reportedName)
}

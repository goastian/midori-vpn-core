package control

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/clientpki"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

const clientPKIUnavailableCode = "client_pki_unavailable"

type enrollDeviceCertificateRequest struct {
	ServerID   string         `json:"server_id"`
	DeviceName string         `json:"device_name"`
	Device     *DeviceRequest `json:"device,omitempty"`
	CSRPEM     string         `json:"csr_pem"`
}

type enrollDeviceCertificateResponse struct {
	Certificate      models.DeviceCertificate `json:"certificate"`
	CACertificatePEM string                   `json:"ca_certificate_pem"`
}

func decodeStrictJSON(body io.Reader, destination any) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// EnrollDeviceCertificate signs a device-created CSR. No API request accepts
// a private key, so Core cannot impersonate an enrolled device.
func (h *Handler) EnrollDeviceCertificate(w http.ResponseWriter, r *http.Request) {
	if h.clientCertificateCA == nil {
		respond.JsonErrorCode(w, "client certificate enrollment is not configured", clientPKIUnavailableCode, http.StatusServiceUnavailable)
		return
	}
	user := auth.GetUser(r)
	var request enrollDeviceCertificateRequest
	if err := decodeStrictJSON(r.Body, &request); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	serverID, err := uuid.Parse(strings.TrimSpace(request.ServerID))
	if err != nil {
		respond.JsonError(w, "invalid server_id", http.StatusBadRequest)
		return
	}
	deviceRequest, err := normalizeDeviceRequest(request.Device, request.DeviceName)
	if err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	server, err := h.serverRepo.GetByID(r.Context(), serverID)
	if err != nil || !server.IsActive {
		respond.JsonError(w, "server not found or inactive", http.StatusNotFound)
		return
	}
	_, hasOpenVPN := configuredServerTransport(server, "openvpn")
	_, hasIKEv2 := configuredServerTransport(server, "ikev2")
	if !hasOpenVPN && !hasIKEv2 {
		respond.JsonError(w, "server has no certificate-based transport enabled", http.StatusConflict)
		return
	}

	certificateID := uuid.New()
	issued, err := h.clientCertificateCA.Issue(request.CSRPEM, certificateID, time.Now())
	if err != nil {
		respond.SafeError(w, "invalid certificate request", err, http.StatusBadRequest)
		return
	}
	device, err := h.resolveCertificateDevice(r.Context(), user.ID, serverID, deviceRequest)
	if errors.Is(err, repo.ErrDeviceRevoked) {
		respond.JsonErrorCode(w, "device is revoked", "device_revoked", http.StatusConflict)
		return
	}
	if err != nil {
		respond.SafeError(w, "failed to resolve certificate device", err, http.StatusInternalServerError)
		return
	}
	certificate := models.DeviceCertificate{
		ID:              certificateID,
		UserID:          user.ID,
		ServerID:        serverID,
		DeviceName:      device.ReportedName,
		DeviceID:        &device.ID,
		SerialNumber:    issued.SerialNumber,
		CertificatePEM:  issued.CertificatePEM,
		PublicKeySHA256: issued.PublicKeySHA256,
		NotBefore:       issued.NotBefore,
		NotAfter:        issued.NotAfter,
	}
	if err := h.clientCertificateRepo.ReplaceActive(r.Context(), &certificate); err != nil {
		respond.SafeError(w, "failed to persist device certificate", err, http.StatusInternalServerError)
		return
	}
	h.auditRepo.LogBestEffort(r.Context(), &user.ID, "certificate.enroll", map[string]interface{}{
		"certificate_id": certificate.ID,
		"device_id":      device.ID,
		"server_id":      certificate.ServerID,
		"device_name":    certificate.DeviceName,
		"not_after":      certificate.NotAfter,
	}, r.RemoteAddr)
	respond.JsonOK(w, enrollDeviceCertificateResponse{
		Certificate: certificate, CACertificatePEM: h.clientCertificateCA.CACertificatePEM(),
	}, http.StatusCreated)
}

func (h *Handler) ListDeviceCertificates(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	certificates, err := h.clientCertificateRepo.ListByUser(r.Context(), user.ID)
	if err != nil {
		respond.SafeError(w, "failed to list device certificates", err, http.StatusInternalServerError)
		return
	}
	for i := range certificates {
		certificates[i].CertificatePEM = ""
	}
	respond.JsonOK(w, certificates, http.StatusOK)
}

func (h *Handler) RevokeDeviceCertificate(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	certificateID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid certificate id", http.StatusBadRequest)
		return
	}
	revoked, err := h.clientCertificateRepo.Revoke(r.Context(), certificateID, user.ID, "cessation_of_operation")
	if err != nil {
		respond.SafeError(w, "failed to revoke device certificate", err, http.StatusInternalServerError)
		return
	}
	if !revoked {
		respond.JsonError(w, "active certificate not found", http.StatusNotFound)
		return
	}
	h.auditRepo.LogBestEffort(r.Context(), &user.ID, "certificate.revoke", map[string]interface{}{
		"certificate_id": certificateID,
	}, r.RemoteAddr)
	respond.JsonOK(w, map[string]string{"status": "revoked"}, http.StatusOK)
}

func (h *Handler) ClientCACertificate(w http.ResponseWriter, r *http.Request) {
	if h.clientCertificateCA == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(h.clientCertificateCA.CACertificatePEM()))
}

func (h *Handler) ClientCertificateCRL(w http.ResponseWriter, r *http.Request) {
	if h.clientCertificateCA == nil {
		http.NotFound(w, r)
		return
	}
	stored, err := h.clientCertificateRepo.ListRevoked(r.Context())
	if err != nil {
		respond.SafeError(w, "failed to build client certificate revocation list", err, http.StatusInternalServerError)
		return
	}
	revoked := make([]clientpki.RevokedCertificate, 0, len(stored))
	for _, entry := range stored {
		revoked = append(revoked, clientpki.RevokedCertificate{
			SerialNumber: entry.SerialNumber, RevokedAt: entry.RevokedAt, Reason: entry.Reason,
		})
	}
	crl, err := h.clientCertificateCA.CreateCRL(revoked, time.Now())
	if err != nil {
		respond.SafeError(w, "failed to build client certificate revocation list", err, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(crl)
}

package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/desiredstate"
	"github.com/goastian/midori-vpn-core/internal/fleetauth"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/nodeplane"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
	"github.com/goastian/midori-vpn-core/internal/telemetry"
)

const maxNodePlaneBody = 64 << 10

type NodePlaneHandler struct {
	repo     *repo.MulticlusterRepo
	verifier *fleetauth.Verifier
}

func NewNodePlaneHandler(pool *pgxpool.Pool, cfg *config.Config) *NodePlaneHandler {
	var replayStore fleetauth.ReplayStore
	if cfg != nil && cfg.RedisURL != "" {
		options, err := redis.ParseURL(cfg.RedisURL)
		if err == nil {
			replayStore = fleetauth.NewRedisReplayStore(redis.NewClient(options))
		}
	} else if cfg == nil || cfg.AppEnv != "production" {
		replayStore = fleetauth.NewMemoryReplayStore()
	}
	return &NodePlaneHandler{
		repo:     repo.NewMulticlusterRepo(pool),
		verifier: fleetauth.NewVerifier(replayStore),
	}
}

func (h *NodePlaneHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	body, err := readNodePlaneBody(r)
	if err != nil {
		respond.JsonError(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	var request nodeplane.EnrollmentRequest
	if err := decodeStrictJSON(bytes.NewReader(body), &request); err != nil {
		respond.JsonError(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	nodeID, err := uuid.Parse(request.NodeID)
	if err != nil || nodeID == uuid.Nil {
		respond.JsonError(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	publicKey, err := fleetauth.DecodePublicKey(request.PublicKey)
	if err != nil {
		respond.JsonError(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	if err := h.verifier.Verify(r.Context(), r, body, nodeID, publicKey); err != nil {
		recordFleetAuthenticationFailure(err)
		if errors.Is(err, fleetauth.ErrReplayProtectionUnavailable) {
			slog.Error("node enrollment replay protection unavailable", "node_id", nodeID)
			respond.JsonError(w, "node enrollment is unavailable", http.StatusServiceUnavailable)
			return
		}
		respond.JsonErrorCode(w, "node enrollment authentication failed", "node_enrollment_unauthorized", http.StatusUnauthorized)
		return
	}
	token, ok := enrollmentBearerToken(r.Header.Get("Authorization"))
	if !ok {
		respond.JsonErrorCode(w, "node enrollment authentication failed", "node_enrollment_unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.repo.EnrollNode(r.Context(), nodeID, token, publicKey); err != nil {
		if errors.Is(err, repo.ErrEnrollmentTokenInvalid) || errors.Is(err, repo.ErrNodeAlreadyEnrolled) ||
			errors.Is(err, repo.ErrNodeNotEnrolling) || errors.Is(err, repo.ErrNodeIdentityConflict) ||
			errors.Is(err, repo.ErrNodeRevoked) || errors.Is(err, pgx.ErrNoRows) {
			respond.JsonErrorCode(w, "node enrollment authentication failed", "node_enrollment_unauthorized", http.StatusUnauthorized)
			return
		}
		slog.Error("node enrollment persistence failed", "node_id", nodeID, "error", err)
		respond.JsonError(w, "node enrollment is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respond.JsonOK(w, map[string]string{"node_id": nodeID.String(), "status": "enrolled"}, http.StatusCreated)
}

func (h *NodePlaneHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	nodeID, err := uuid.Parse(r.Header.Get(fleetauth.HeaderNodeID))
	if err != nil || nodeID == uuid.Nil {
		respond.JsonErrorCode(w, "invalid node signature", "node_authentication_failed", http.StatusUnauthorized)
		return
	}
	publicKey, err := h.repo.NodeIdentity(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, repo.ErrNodeRevoked) || errors.Is(err, repo.ErrNodeIdentityUnavailable) || errors.Is(err, pgx.ErrNoRows) {
			respond.JsonErrorCode(w, "invalid node signature", "node_authentication_failed", http.StatusUnauthorized)
			return
		}
		slog.Error("node identity lookup failed", "node_id", nodeID, "error", err)
		respond.JsonError(w, "node authentication is unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := readNodePlaneBody(r)
	if err != nil {
		respond.JsonError(w, "invalid heartbeat request", http.StatusBadRequest)
		return
	}
	if err := h.verifier.Verify(r.Context(), r, body, nodeID, publicKey); err != nil {
		recordFleetAuthenticationFailure(err)
		if errors.Is(err, fleetauth.ErrReplayProtectionUnavailable) {
			slog.Error("node heartbeat replay protection unavailable", "node_id", nodeID)
			respond.JsonError(w, "node authentication is unavailable", http.StatusServiceUnavailable)
			return
		}
		respond.JsonErrorCode(w, "invalid node signature", "node_authentication_failed", http.StatusUnauthorized)
		return
	}
	var request nodeplane.HeartbeatRequest
	if err := decodeStrictJSON(bytes.NewReader(body), &request); err != nil || !validHeartbeat(request, time.Now().UTC()) {
		respond.JsonError(w, "invalid heartbeat request", http.StatusBadRequest)
		return
	}
	observation := &models.NodeObservation{
		NodeID:            nodeID,
		AppliedRevision:   request.AppliedRevision,
		CoreVersion:       request.CoreVersion,
		HealthStatus:      request.HealthStatus,
		VersionCompatible: request.VersionCompatible,
		CurrentPeers:      request.CurrentPeers,
		MaxPeers:          request.MaxPeers,
		TransportStates:   request.TransportStates,
		LastErrorCode:     request.LastErrorCode,
		ReportedAt:        request.ReportedAt,
	}
	if err := h.repo.RecordObservation(r.Context(), observation); err != nil {
		if errors.Is(err, repo.ErrNodeRevoked) || errors.Is(err, repo.ErrNodeIdentityUnavailable) {
			respond.JsonErrorCode(w, "invalid node signature", "node_authentication_failed", http.StatusUnauthorized)
			return
		}
		slog.Error("node heartbeat persistence failed", "node_id", nodeID, "error", err)
		respond.JsonError(w, "node heartbeat is unavailable", http.StatusServiceUnavailable)
		return
	}
	respond.JsonOK(w, map[string]any{
		"node_id":     nodeID,
		"received_at": observation.ReceivedAt,
	}, http.StatusOK)
}

// DesiredState returns only the latest revision for the authenticated node.
// The empty GET body is still covered by the node's anti-replay signature.
func (h *NodePlaneHandler) DesiredState(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := h.authenticateNodeRequest(w, r, nil)
	if !ok {
		return
	}
	revision, err := h.repo.LatestDesiredRevision(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, repo.ErrNodeRevoked) || errors.Is(err, repo.ErrNodeIdentityUnavailable) {
			respond.JsonErrorCode(w, "invalid node signature", "node_authentication_failed", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		slog.Error("desired state lookup failed", "node_id", nodeID, "error", err)
		respond.JsonErrorCode(w, "desired state is unavailable", "desired_state_unavailable", http.StatusServiceUnavailable)
		return
	}
	signed, err := desiredstate.DecodeStored(
		revision.Payload, revision.PayloadSHA256, revision.Signature, revision.SigningKeyID,
	)
	if err != nil {
		slog.Error("stored desired state is invalid", "node_id", nodeID, "revision", revision.Revision)
		respond.JsonErrorCode(w, "desired state is unavailable", "desired_state_invalid", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respond.JsonOK(w, signed, http.StatusOK)
}

func (h *NodePlaneHandler) authenticateNodeRequest(w http.ResponseWriter, r *http.Request, body []byte) (uuid.UUID, bool) {
	nodeID, err := uuid.Parse(r.Header.Get(fleetauth.HeaderNodeID))
	if err != nil || nodeID == uuid.Nil {
		respond.JsonErrorCode(w, "invalid node signature", "node_authentication_failed", http.StatusUnauthorized)
		return uuid.Nil, false
	}
	publicKey, err := h.repo.NodeIdentity(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, repo.ErrNodeRevoked) || errors.Is(err, repo.ErrNodeIdentityUnavailable) || errors.Is(err, pgx.ErrNoRows) {
			respond.JsonErrorCode(w, "invalid node signature", "node_authentication_failed", http.StatusUnauthorized)
			return uuid.Nil, false
		}
		slog.Error("node identity lookup failed", "node_id", nodeID, "error", err)
		respond.JsonError(w, "node authentication is unavailable", http.StatusServiceUnavailable)
		return uuid.Nil, false
	}
	if err := h.verifier.Verify(r.Context(), r, body, nodeID, publicKey); err != nil {
		recordFleetAuthenticationFailure(err)
		if errors.Is(err, fleetauth.ErrReplayProtectionUnavailable) {
			slog.Error("node request replay protection unavailable", "node_id", nodeID)
			respond.JsonError(w, "node authentication is unavailable", http.StatusServiceUnavailable)
			return uuid.Nil, false
		}
		respond.JsonErrorCode(w, "invalid node signature", "node_authentication_failed", http.StatusUnauthorized)
		return uuid.Nil, false
	}
	return nodeID, true
}

func recordFleetAuthenticationFailure(err error) {
	reason := telemetry.NodeAuthInvalid
	if errors.Is(err, fleetauth.ErrReplayDetected) {
		reason = telemetry.NodeAuthReplay
	} else if errors.Is(err, fleetauth.ErrReplayProtectionUnavailable) {
		reason = telemetry.NodeAuthUnavailable
	}
	telemetry.RecordNodeAuthFailure(reason)
}

var multiclusterStates = []string{
	"all", "enrolling", "inactive", "active", "draining", "revoked", "retired",
}

func (h *Handler) AdminListClusters(w http.ResponseWriter, r *http.Request) {
	query, ok := requirePageQuery(w, r, pageQueryConfig{
		DefaultSort: "name",
		Sorts:       []string{"name", "region", "node_count", "created_at"},
		Statuses:    multiclusterStates,
		AllowSearch: true,
	})
	if !ok {
		return
	}
	clusters, total, err := h.multiclusterRepo.ListAdminClusters(r.Context(), query.ListOptions())
	if err != nil {
		slog.Error("admin list clusters error", "error", err)
		respond.JsonError(w, "failed to list clusters", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, newPageResponse(clusters, query, total), http.StatusOK)
}

func (h *Handler) AdminListCoreNodes(w http.ResponseWriter, r *http.Request) {
	clusterID, err := uuid.Parse(chi.URLParam(r, "clusterID"))
	if err != nil || clusterID == uuid.Nil {
		respond.JsonError(w, "invalid cluster ID", http.StatusBadRequest)
		return
	}
	query, ok := requirePageQuery(w, r, pageQueryConfig{
		DefaultSort: "name",
		Sorts:       []string{"name", "created_at", "last_seen_at", "core_version"},
		Statuses:    multiclusterStates,
		AllowSearch: true,
	})
	if !ok {
		return
	}
	nodes, total, err := h.multiclusterRepo.ListAdminNodes(r.Context(), clusterID, query.ListOptions())
	if err != nil {
		slog.Error("admin list Core nodes error", "cluster_id", clusterID, "error", err)
		respond.JsonError(w, "failed to list Core nodes", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, newPageResponse(nodes, query, total), http.StatusOK)
}

func (h *Handler) AdminCreateCluster(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name         string            `json:"name"`
		Region       string            `json:"region"`
		PolicyLabels map[string]string `json:"policy_labels"`
		IsPrincipal  bool              `json:"is_principal"`
	}
	if err := decodeRequestJSON(r, &request); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	cluster := &models.Cluster{
		Name: request.Name, Region: request.Region, State: models.ClusterStateInactive,
		PolicyLabels: request.PolicyLabels, IsPrincipal: request.IsPrincipal,
	}
	if err := h.multiclusterRepo.CreateCluster(r.Context(), cluster); err != nil {
		respond.JsonError(w, "failed to create cluster", http.StatusBadRequest)
		return
	}
	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.cluster.create", map[string]any{"cluster_id": cluster.ID}, r.RemoteAddr)
	respond.JsonOK(w, cluster, http.StatusCreated)
}

func (h *Handler) AdminCreateCoreNode(w http.ResponseWriter, r *http.Request) {
	clusterID, err := uuid.Parse(chi.URLParam(r, "clusterID"))
	if err != nil {
		respond.JsonError(w, "invalid cluster ID", http.StatusBadRequest)
		return
	}
	var request struct {
		Name           string `json:"name"`
		ManagementHost string `json:"management_host"`
	}
	if err := decodeRequestJSON(r, &request); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	node := &models.CoreNode{
		ClusterID: clusterID, Name: request.Name, ManagementHost: request.ManagementHost,
		State: models.ClusterStateEnrolling,
	}
	if err := h.multiclusterRepo.CreateNode(r.Context(), node); err != nil {
		if errors.Is(err, repo.ErrClusterUnavailable) {
			respond.JsonErrorCode(w, "cluster cannot accept Core nodes", "cluster_unavailable", http.StatusConflict)
			return
		}
		respond.JsonError(w, "failed to create Core node", http.StatusBadRequest)
		return
	}
	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.core-node.create", map[string]any{"node_id": node.ID}, r.RemoteAddr)
	respond.JsonOK(w, node, http.StatusCreated)
}

func (h *Handler) AdminIssueNodeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	nodeID, err := uuid.Parse(chi.URLParam(r, "nodeID"))
	if err != nil {
		respond.JsonError(w, "invalid node ID", http.StatusBadRequest)
		return
	}
	var request struct {
		TTLMinutes int `json:"ttl_minutes"`
	}
	if err := decodeRequestJSON(r, &request); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if request.TTLMinutes == 0 {
		request.TTLMinutes = 15
	}
	if request.TTLMinutes < 1 || request.TTLMinutes > 24*60 {
		respond.JsonError(w, "enrollment token TTL must be between 1 and 1440 minutes", http.StatusBadRequest)
		return
	}
	token, err := h.multiclusterRepo.IssueEnrollmentToken(r.Context(), nodeID, time.Duration(request.TTLMinutes)*time.Minute)
	if err != nil {
		respond.JsonError(w, "failed to issue enrollment token", http.StatusConflict)
		return
	}
	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.core-node.enrollment-token.issue", map[string]any{"node_id": nodeID, "expires_at": token.ExpiresAt}, r.RemoteAddr)
	w.Header().Set("Cache-Control", "no-store")
	respond.JsonOK(w, token, http.StatusCreated)
}

func (h *Handler) AdminRevokeCoreNode(w http.ResponseWriter, r *http.Request) {
	nodeID, err := uuid.Parse(chi.URLParam(r, "nodeID"))
	if err != nil {
		respond.JsonError(w, "invalid node ID", http.StatusBadRequest)
		return
	}
	if err := h.multiclusterRepo.RevokeNode(r.Context(), nodeID); err != nil {
		respond.JsonError(w, "failed to revoke Core node", http.StatusConflict)
		return
	}
	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.core-node.revoke", map[string]any{"node_id": nodeID}, r.RemoteAddr)
	respond.JsonOK(w, map[string]string{"node_id": nodeID.String(), "status": "revoked"}, http.StatusOK)
}

type desiredStateCreateRequest struct {
	ExpectedPreviousRevision json.RawMessage                `json:"expected_previous_revision"`
	ExpiresInSeconds         int                            `json:"expires_in_seconds"`
	MinimumCoreVersion       string                         `json:"minimum_core_version"`
	PublicEndpoints          []desiredstate.PublicEndpoint  `json:"public_endpoints"`
	Capacity                 desiredstate.Capacity          `json:"capacity"`
	Transports               []desiredstate.Transport       `json:"transports"`
	SecretReferences         []desiredstate.SecretReference `json:"secret_references"`
}

func (h *Handler) AdminCreateDesiredState(w http.ResponseWriter, r *http.Request) {
	if h.desiredStateSigner == nil {
		respond.JsonErrorCode(w, "desired state signing is unavailable", "desired_state_signing_unavailable", http.StatusServiceUnavailable)
		return
	}
	nodeID, err := uuid.Parse(chi.URLParam(r, "nodeID"))
	if err != nil || nodeID == uuid.Nil {
		respond.JsonError(w, "invalid node ID", http.StatusBadRequest)
		return
	}
	var request desiredStateCreateRequest
	if err := decodeRequestJSON(r, &request); err != nil {
		respond.JsonError(w, "invalid desired state request", http.StatusBadRequest)
		return
	}
	expectedPrevious, err := parseExpectedPreviousRevision(request.ExpectedPreviousRevision)
	if err != nil {
		respond.JsonError(w, "expected_previous_revision must be an integer or null", http.StatusBadRequest)
		return
	}
	if request.ExpiresInSeconds == 0 {
		request.ExpiresInSeconds = 900
	}
	if request.ExpiresInSeconds < 60 || request.ExpiresInSeconds > 86400 {
		respond.JsonError(w, "expires_in_seconds must be between 60 and 86400", http.StatusBadRequest)
		return
	}
	desiredContext, err := h.multiclusterRepo.DesiredContext(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, repo.ErrNodeRevoked) || errors.Is(err, repo.ErrNodeIdentityUnavailable) || errors.Is(err, pgx.ErrNoRows) {
			respond.JsonErrorCode(w, "Core node cannot accept desired state", "desired_state_node_unavailable", http.StatusConflict)
			return
		}
		slog.Error("desired state context lookup failed", "node_id", nodeID, "error", err)
		respond.JsonErrorCode(w, "desired state is unavailable", "desired_state_unavailable", http.StatusServiceUnavailable)
		return
	}
	if !sameRevision(expectedPrevious, desiredContext.PreviousRevision) {
		respond.JsonErrorCode(w, "desired state revision has changed", "desired_state_revision_conflict", http.StatusConflict)
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	bundle := desiredstate.Bundle{
		SchemaVersion: desiredstate.SchemaVersion, ClusterID: desiredContext.ClusterID, NodeID: nodeID,
		Revision: desiredContext.NextRevision, PreviousRevision: desiredContext.PreviousRevision,
		IssuedAt: now, ExpiresAt: now.Add(time.Duration(request.ExpiresInSeconds) * time.Second),
		MinimumCoreVersion: request.MinimumCoreVersion,
		ManagementEndpoint: strings.TrimRight(h.publicManagementEndpoint(), "/"),
		PublicEndpoints:    request.PublicEndpoints, Capacity: request.Capacity,
		Transports: request.Transports, SecretReferences: request.SecretReferences,
	}
	signed, payload, digest, err := h.desiredStateSigner.Sign(bundle)
	if err != nil {
		respond.JsonErrorCode(w, "invalid desired state", "desired_state_invalid", http.StatusBadRequest)
		return
	}
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	revision := &models.DesiredRevision{
		NodeID: nodeID, Revision: signed.Bundle.Revision, PreviousRevision: signed.Bundle.PreviousRevision,
		SchemaVersion: signed.Bundle.SchemaVersion, MinimumCoreVersion: signed.Bundle.MinimumCoreVersion,
		Payload: payload, PayloadSHA256: digest, Signature: signature,
		SigningKeyID: signed.SigningKeyID, IssuedAt: signed.Bundle.IssuedAt, ExpiresAt: signed.Bundle.ExpiresAt,
	}
	if err := h.multiclusterRepo.CreateDesiredRevision(r.Context(), revision); err != nil {
		if errors.Is(err, repo.ErrDesiredRevisionConflict) {
			respond.JsonErrorCode(w, "desired state revision has changed", "desired_state_revision_conflict", http.StatusConflict)
			return
		}
		slog.Error("desired state persistence failed", "node_id", nodeID, "error", err)
		respond.JsonErrorCode(w, "desired state is unavailable", "desired_state_unavailable", http.StatusServiceUnavailable)
		return
	}
	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.core-node.desired-state.create", map[string]any{"node_id": nodeID, "revision": revision.Revision}, r.RemoteAddr)
	w.Header().Set("Cache-Control", "no-store")
	respond.JsonOK(w, signed, http.StatusCreated)
}

func (h *Handler) publicManagementEndpoint() string {
	// PUBLIC_BASE_URL is a trusted deployment origin and never comes from the
	// request Host header. Regional nodes use the same origin for node-plane API.
	return h.publicBaseURL
}

func parseExpectedPreviousRevision(raw json.RawMessage) (*int64, error) {
	if raw == nil {
		return nil, errors.New("expected previous revision is required")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil || value < 1 {
		return nil, errors.New("expected previous revision is invalid")
	}
	return &value, nil
}

func sameRevision(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func readNodePlaneBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxNodePlaneBody+1))
	if err != nil || len(body) == 0 || len(body) > maxNodePlaneBody {
		return nil, errors.New("invalid node-plane body")
	}
	return body, nil
}

func decodeRequestJSON(r *http.Request, destination any) error {
	body, err := readNodePlaneBody(r)
	if err != nil {
		return err
	}
	return decodeStrictJSON(bytes.NewReader(body), destination)
}

func enrollmentBearerToken(value string) (string, bool) {
	if !strings.HasPrefix(value, "Bearer ") || strings.Contains(value[7:], " ") {
		return "", false
	}
	token := value[7:]
	return token, len(token) == 43
}

func validHeartbeat(request nodeplane.HeartbeatRequest, now time.Time) bool {
	if request.SchemaVersion != nodeplane.SchemaVersion || len(request.CoreVersion) < 1 || len(request.CoreVersion) > 64 ||
		request.CurrentPeers < 0 || request.MaxPeers < 0 ||
		request.ReportedAt.IsZero() || request.ReportedAt.Before(now.Add(-2*time.Minute)) || request.ReportedAt.After(now.Add(30*time.Second)) ||
		len(request.TransportStates) > 6 {
		return false
	}
	switch request.HealthStatus {
	case "unknown", "healthy", "degraded", "error":
	default:
		return false
	}
	if request.LastErrorCode != "" {
		if len(request.LastErrorCode) > 64 {
			return false
		}
		for _, character := range request.LastErrorCode {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
				return false
			}
		}
	}
	allowedProtocols := map[string]struct{}{
		"wireguard": {}, "wss": {}, "masque": {}, "openvpn": {}, "ikev2": {}, "proxy": {},
	}
	for protocol, state := range request.TransportStates {
		if _, ok := allowedProtocols[protocol]; !ok {
			return false
		}
		switch state.Status {
		case "unknown", "healthy", "degraded", "error", "disabled":
		default:
			return false
		}
	}
	return true
}

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type ClusterState string

const (
	ClusterStateEnrolling ClusterState = "enrolling"
	ClusterStateInactive  ClusterState = "inactive"
	ClusterStateActive    ClusterState = "active"
	ClusterStateDraining  ClusterState = "draining"
	ClusterStateRevoked   ClusterState = "revoked"
	ClusterStateRetired   ClusterState = "retired"
)

func (state ClusterState) Valid() bool {
	switch state {
	case ClusterStateEnrolling, ClusterStateInactive, ClusterStateActive,
		ClusterStateDraining, ClusterStateRevoked, ClusterStateRetired:
		return true
	default:
		return false
	}
}

type Cluster struct {
	ID           uuid.UUID         `json:"id"`
	Name         string            `json:"name"`
	Region       string            `json:"region"`
	State        ClusterState      `json:"state"`
	PolicyLabels map[string]string `json:"policy_labels"`
	IsPrincipal  bool              `json:"is_principal"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

type CoreNode struct {
	ID                uuid.UUID    `json:"id"`
	ClusterID         uuid.UUID    `json:"cluster_id"`
	Name              string       `json:"name"`
	ManagementHost    string       `json:"management_host"`
	State             ClusterState `json:"state"`
	CoreVersion       string       `json:"core_version"`
	IdentityPublicKey string       `json:"identity_public_key,omitempty"`
	EnrolledAt        *time.Time   `json:"enrolled_at,omitempty"`
	LastSeenAt        *time.Time   `json:"last_seen_at,omitempty"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

type NodeEnrollmentToken struct {
	NodeID    uuid.UUID `json:"node_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type DesiredRevision struct {
	ID                 uuid.UUID       `json:"id"`
	NodeID             uuid.UUID       `json:"node_id"`
	Revision           int64           `json:"revision"`
	PreviousRevision   *int64          `json:"previous_revision,omitempty"`
	SchemaVersion      int             `json:"schema_version"`
	MinimumCoreVersion string          `json:"minimum_core_version"`
	Payload            json.RawMessage `json:"payload"`
	PayloadSHA256      []byte          `json:"payload_sha256"`
	Signature          []byte          `json:"-"`
	SigningKeyID       string          `json:"signing_key_id"`
	IssuedAt           time.Time       `json:"issued_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
	CreatedAt          time.Time       `json:"created_at"`
}

type NodeTransportState struct {
	Status    string `json:"status"`
	Certified bool   `json:"certified"`
}

type NodeObservation struct {
	ID                uuid.UUID                     `json:"id"`
	NodeID            uuid.UUID                     `json:"node_id"`
	AppliedRevision   *int64                        `json:"applied_revision,omitempty"`
	CoreVersion       string                        `json:"core_version"`
	HealthStatus      string                        `json:"health_status"`
	VersionCompatible bool                          `json:"version_compatible"`
	CurrentPeers      int                           `json:"current_peers"`
	MaxPeers          int                           `json:"max_peers"`
	TransportStates   map[string]NodeTransportState `json:"transport_states"`
	LastErrorCode     string                        `json:"last_error_code,omitempty"`
	ReportedAt        time.Time                     `json:"reported_at"`
	ReceivedAt        time.Time                     `json:"received_at"`
}

// AdminClusterSummary contains only non-sensitive fleet inventory fields.
// Enrollment material and signing identities are deliberately absent.
type AdminClusterSummary struct {
	ID               uuid.UUID         `json:"id"`
	Name             string            `json:"name"`
	Region           string            `json:"region"`
	State            ClusterState      `json:"state"`
	PolicyLabels     map[string]string `json:"policy_labels"`
	IsPrincipal      bool              `json:"is_principal"`
	NodeCount        int               `json:"node_count"`
	ActiveNodeCount  int               `json:"active_node_count"`
	HealthyNodeCount int               `json:"healthy_node_count"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// AdminCoreNodeSummary is the safe Control projection of one Core node. It
// exposes the latest desired/observed metadata but never token hashes,
// identity keys, desired payloads, digests or signatures.
type AdminCoreNodeSummary struct {
	ID                 uuid.UUID                     `json:"id"`
	ClusterID          uuid.UUID                     `json:"cluster_id"`
	Name               string                        `json:"name"`
	ManagementHost     string                        `json:"management_host"`
	State              ClusterState                  `json:"state"`
	CoreVersion        string                        `json:"core_version"`
	Enrolled           bool                          `json:"enrolled"`
	EnrolledAt         *time.Time                    `json:"enrolled_at"`
	LastSeenAt         *time.Time                    `json:"last_seen_at"`
	DesiredRevision    *int64                        `json:"desired_revision"`
	DesiredExpiresAt   *time.Time                    `json:"desired_expires_at"`
	MinimumCoreVersion string                        `json:"minimum_core_version"`
	AppliedRevision    *int64                        `json:"applied_revision"`
	HealthStatus       string                        `json:"health_status"`
	VersionCompatible  *bool                         `json:"version_compatible"`
	CurrentPeers       *int                          `json:"current_peers"`
	MaxPeers           *int                          `json:"max_peers"`
	TransportStates    map[string]NodeTransportState `json:"transport_states"`
	LastErrorCode      string                        `json:"last_error_code"`
	ObservedAt         *time.Time                    `json:"observed_at"`
	ServerID           *uuid.UUID                    `json:"server_id"`
	ServerName         string                        `json:"server_name"`
	PlacementReady     bool                          `json:"placement_ready"`
	PlacementReason    string                        `json:"placement_reason"`
	CreatedAt          time.Time                     `json:"created_at"`
	UpdatedAt          time.Time                     `json:"updated_at"`
}

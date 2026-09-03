// Package nodeplane implements the enrolled Core node client protocol to the
// central Control plane.
package nodeplane

import (
	"time"

	"github.com/goastian/midori-vpn-core/internal/models"
)

const (
	EnrollmentPath   = "/api/v1/node/enroll"
	HeartbeatPath    = "/api/v1/node/heartbeat"
	DesiredStatePath = "/api/v1/node/desired-state"
	SchemaVersion    = 1
)

type EnrollmentRequest struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
}

type HeartbeatRequest struct {
	SchemaVersion     int                                  `json:"schema_version"`
	AppliedRevision   *int64                               `json:"applied_revision,omitempty"`
	CoreVersion       string                               `json:"core_version"`
	HealthStatus      string                               `json:"health_status"`
	CurrentPeers      int                                  `json:"current_peers"`
	MaxPeers          int                                  `json:"max_peers"`
	VersionCompatible bool                                 `json:"version_compatible"`
	TransportStates   map[string]models.NodeTransportState `json:"transport_states"`
	LastErrorCode     string                               `json:"last_error_code,omitempty"`
	ReportedAt        time.Time                            `json:"reported_at"`
}

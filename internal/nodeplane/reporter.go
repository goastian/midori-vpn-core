package nodeplane

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"time"

	"github.com/goastian/midori-vpn-core/internal/desiredstate"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

const DefaultHeartbeatInterval = 30 * time.Second

type StatsProvider interface {
	ServerStats() (*wg.ServerStatsResponse, error)
}

type Reporter struct {
	client        *Client
	stats         StatsProvider
	coreVersion   string
	maxPeers      int
	interval      time.Duration
	now           func() time.Time
	tokenPath     string
	reportOutcome func(error)
	desired       *desiredstate.Activator
	jitter        func() time.Duration
}

func NewReporter(client *Client, stats StatsProvider, coreVersion string, maxPeers int, tokenPath string, reportOutcome func(error)) (*Reporter, error) {
	if client == nil || stats == nil {
		return nil, errors.New("node-plane client and stats provider are required")
	}
	if coreVersion == "" || len(coreVersion) > 64 || maxPeers < 1 {
		return nil, errors.New("valid Core version and positive node capacity are required")
	}
	return &Reporter{
		client: client, stats: stats, coreVersion: coreVersion, maxPeers: maxPeers,
		interval: DefaultHeartbeatInterval, now: time.Now, tokenPath: tokenPath,
		reportOutcome: reportOutcome, jitter: heartbeatJitter,
	}, nil
}

func (r *Reporter) SetDesiredState(activator *desiredstate.Activator) {
	r.desired = activator
}

func (r *Reporter) Run(ctx context.Context) {
	r.report(ctx)
	for {
		delay := r.interval + r.jitter()
		if delay < time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			r.report(ctx)
		}
	}
}

func (r *Reporter) report(ctx context.Context) {
	if r.tokenPath != "" {
		exists, err := EnrollmentTokenExists(r.tokenPath)
		if err != nil {
			r.outcome(err)
			return
		}
		if exists {
			if err := r.client.EnrollFromTokenFile(ctx, r.tokenPath); err != nil {
				r.outcome(err)
				return
			}
		}
	}
	var desiredErr error
	if r.desired != nil {
		signed, available, err := r.client.FetchDesiredState(ctx)
		if err != nil {
			desiredErr = err
		} else if available {
			desiredErr = r.desired.Apply(*signed)
		}
	}
	stats, err := r.stats.ServerStats()
	heartbeat := HeartbeatRequest{
		SchemaVersion:     SchemaVersion,
		CoreVersion:       r.coreVersion,
		HealthStatus:      "healthy",
		MaxPeers:          r.maxPeers,
		VersionCompatible: false,
		TransportStates: map[string]models.NodeTransportState{
			"wireguard": {Status: "healthy", Certified: false},
		},
		ReportedAt: r.now().UTC(),
	}
	if r.desired != nil {
		snapshot := r.desired.Snapshot()
		heartbeat.AppliedRevision = snapshot.AppliedRevision
		heartbeat.VersionCompatible = snapshot.VersionCompatible
		if snapshot.MaxPeers > 0 {
			heartbeat.MaxPeers = snapshot.MaxPeers
		}
		if snapshot.AppliedRevision != nil {
			heartbeat.TransportStates = make(map[string]models.NodeTransportState, len(snapshot.Transports))
		}
		for _, transport := range snapshot.Transports {
			status := "disabled"
			if transport.Enabled {
				status = "unknown"
			}
			heartbeat.TransportStates[transport.Protocol] = models.NodeTransportState{Status: status, Certified: false}
		}
	}
	if err != nil {
		heartbeat.HealthStatus = "error"
		heartbeat.LastErrorCode = "core_peer_state_unavailable"
		heartbeat.TransportStates["wireguard"] = models.NodeTransportState{Status: "error", Certified: false}
	} else {
		heartbeat.CurrentPeers = stats.PeerCount
		if heartbeat.CurrentPeers > heartbeat.MaxPeers {
			if r.desired == nil {
				heartbeat.MaxPeers = heartbeat.CurrentPeers
			} else {
				heartbeat.HealthStatus = "degraded"
				heartbeat.LastErrorCode = "desired_state_capacity_exceeded"
			}
		}
		if state, configured := heartbeat.TransportStates["wireguard"]; configured && state.Status != "disabled" {
			heartbeat.TransportStates["wireguard"] = models.NodeTransportState{Status: "healthy", Certified: false}
		}
	}
	if desiredErr != nil {
		if heartbeat.HealthStatus == "healthy" {
			heartbeat.HealthStatus = "degraded"
		}
		heartbeat.LastErrorCode = desiredStateErrorCode(desiredErr)
	}
	r.outcome(r.client.Heartbeat(ctx, heartbeat))
}

func desiredStateErrorCode(err error) string {
	switch {
	case errors.Is(err, desiredstate.ErrInvalidSignature), errors.Is(err, desiredstate.ErrUntrustedSigningKey):
		return "desired_state_signature_invalid"
	case errors.Is(err, desiredstate.ErrWrongTarget):
		return "desired_state_wrong_target"
	case errors.Is(err, desiredstate.ErrExpired):
		return "desired_state_expired"
	case errors.Is(err, desiredstate.ErrNotYetValid):
		return "desired_state_not_yet_valid"
	case errors.Is(err, desiredstate.ErrIncompatibleVersion):
		return "desired_state_version_incompatible"
	case errors.Is(err, desiredstate.ErrRollback):
		return "desired_state_rollback_rejected"
	case errors.Is(err, desiredstate.ErrBrokenChain):
		return "desired_state_chain_invalid"
	case errors.Is(err, desiredstate.ErrLocalCapability):
		return "desired_state_capability_unavailable"
	case errors.Is(err, desiredstate.ErrInvalidBundle):
		return "desired_state_invalid"
	default:
		return "desired_state_unavailable"
	}
}

func heartbeatJitter() time.Duration {
	var random [2]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		return 0
	}
	milliseconds := int(random[0])<<8 | int(random[1])
	return time.Duration(milliseconds%6001-3000) * time.Millisecond
}

func (r *Reporter) outcome(err error) {
	if r.reportOutcome != nil {
		r.reportOutcome(err)
	}
}

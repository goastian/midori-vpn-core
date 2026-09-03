package nodeplane

import (
	"context"
	"errors"
	"time"

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
		reportOutcome: reportOutcome,
	}, nil
}

func (r *Reporter) Run(ctx context.Context) {
	r.report(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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
	stats, err := r.stats.ServerStats()
	heartbeat := HeartbeatRequest{
		SchemaVersion: SchemaVersion,
		CoreVersion:   r.coreVersion,
		HealthStatus:  "healthy",
		MaxPeers:      r.maxPeers,
		TransportStates: map[string]models.NodeTransportState{
			"wireguard": {Status: "healthy", Certified: false},
		},
		ReportedAt: r.now().UTC(),
	}
	if err != nil {
		heartbeat.HealthStatus = "error"
		heartbeat.LastErrorCode = "core_peer_state_unavailable"
		heartbeat.TransportStates["wireguard"] = models.NodeTransportState{Status: "error", Certified: false}
	} else {
		heartbeat.CurrentPeers = stats.PeerCount
		if heartbeat.CurrentPeers > heartbeat.MaxPeers {
			heartbeat.MaxPeers = heartbeat.CurrentPeers
		}
	}
	r.outcome(r.client.Heartbeat(ctx, heartbeat))
}

func (r *Reporter) outcome(err error) {
	if r.reportOutcome != nil {
		r.reportOutcome(err)
	}
}

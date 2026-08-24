package control

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const (
	transportHealthInterval = 30 * time.Second
	transportHealthTimeout  = 5 * time.Second
	transportHealthRunLimit = 25 * time.Second
)

// StartTransportHealthSync continuously verifies the transports that can be
// probed without client credentials. Protocols that need a complete negotiated
// session remain unknown and therefore cannot be selected by clients.
func StartTransportHealthSync(parentCtx context.Context, pool *pgxpool.Pool) {
	serverRepo := repo.NewServerRepo(pool)
	check := func() {
		ctx, cancel := context.WithTimeout(parentCtx, transportHealthRunLimit)
		defer cancel()
		if err := syncTransportHealth(ctx, serverRepo); err != nil && parentCtx.Err() == nil {
			slog.Error("transport health sync failed", "error", err)
		}
	}

	slog.Info("job started", "job", "transport-health", "interval", transportHealthInterval.String())
	check()
	ticker := time.NewTicker(transportHealthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-parentCtx.Done():
			slog.Info("job stopped", "job", "transport-health")
			return
		case <-ticker.C:
			check()
		}
	}
}

func syncTransportHealth(ctx context.Context, serverRepo *repo.ServerRepo) error {
	servers, err := serverRepo.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("list servers: %w", err)
	}
	for i := range servers {
		server := &servers[i]
		for _, transport := range server.Transports {
			if !transport.Enabled {
				continue
			}
			status, checked := probeTransport(ctx, server, transport)
			if !checked {
				continue
			}
			checkedAt := time.Now().UTC()
			if err := serverRepo.UpdateTransportHealth(ctx, server.ID, transport.Protocol, status, checkedAt); err != nil {
				slog.Error("transport health update failed", "server_id", server.ID, "protocol", transport.Protocol, "error", err)
			}
		}
	}
	return nil
}

func probeTransport(ctx context.Context, server *models.VPNServer, transport models.TransportCapability) (string, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, transportHealthTimeout)
	defer cancel()
	var healthy bool
	switch transport.Protocol {
	case "wireguard":
		healthy = probeCoreReadiness(probeCtx, server)
	case "wss":
		healthy = probeWSS(probeCtx, transport)
	case "proxy":
		healthy = probeTLSProxy(probeCtx, transport)
	case "masque":
		healthy = probeMASQUE(probeCtx, transport)
	default:
		return "unknown", false
	}
	if healthy {
		return "healthy", true
	}
	return "degraded", true
}

func probeMASQUE(ctx context.Context, transport models.TransportCapability) bool {
	templateText, ok := transport.Metadata["uri_template"].(string)
	if !ok {
		return false
	}
	template, err := uritemplate.New(templateText)
	if err != nil {
		return false
	}
	expandedTemplate, err := template.Expand(uritemplate.Values{
		"target_host": uritemplate.String("127.0.0.1"),
		"target_port": uritemplate.String("1"),
	})
	if err != nil {
		return false
	}
	templateURL, err := url.Parse(expandedTemplate)
	if err != nil || templateURL.Scheme != "https" || templateURL.Path == "" || strings.Contains(templateURL.Path, "{") {
		return false
	}
	probeURL := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(transport.Host, strconv.Itoa(transport.Port)),
		Path:   templateURL.Path,
	}
	h3Transport := &http3.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: transport.Host},
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
	}
	defer h3Transport.Close()
	client := &http.Client{Transport: h3Transport}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusTooManyRequests
}

func probeCoreReadiness(ctx context.Context, server *models.VPNServer) bool {
	readyURL, _, err := coreURL(server, "/readyz")
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, readyURL, nil)
	if err != nil {
		return false
	}
	resp, err := coreHTTP.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func probeWSS(ctx context.Context, transport models.TransportCapability) bool {
	probeURL := url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(transport.Host, strconv.Itoa(transport.Port)),
		Path:   "/api/v1/tunnel/ws",
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return false
	}
	resp, err := coreHTTP.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusTooManyRequests
}

func probeTLSProxy(ctx context.Context, transport models.TransportCapability) bool {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: transportHealthTimeout},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: transport.Host,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(transport.Host, strconv.Itoa(transport.Port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(transportHealthTimeout))
	if _, err := fmt.Fprint(conn, "CONNECT health.invalid:443 HTTP/1.1\r\nHost: health.invalid:443\r\n\r\n"); err != nil {
		return false
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusProxyAuthRequired
}

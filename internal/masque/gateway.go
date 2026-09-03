package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/goastian/midori-vpn-core/internal/httpx"
	"github.com/goastian/midori-vpn-core/internal/proxytoken"
	"github.com/google/uuid"
	masquego "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// Gateway is an authenticated RFC 9298 CONNECT-UDP proxy restricted to the
// local WireGuard socket. It never acts as a general-purpose UDP proxy.
type Gateway struct {
	server     *http3.Server
	proxy      *masquego.Proxy
	template   *uritemplate.Template
	target     *net.UDPAddr
	secret     string
	serverID   uuid.UUID
	active     atomic.Int64
	maxClients int64
}

func NewGateway(addr, certFile, keyFile, templateText string, wgPort int, secret string, serverID uuid.UUID, maxClients int) (*Gateway, error) {
	template, err := uritemplate.New(templateText)
	if err != nil {
		return nil, fmt.Errorf("parse MASQUE URI template: %w", err)
	}
	expandedTemplate, err := template.Expand(uritemplate.Values{
		"target_host": uritemplate.String("127.0.0.1"),
		"target_port": uritemplate.String(strconv.Itoa(wgPort)),
	})
	if err != nil {
		return nil, fmt.Errorf("expand MASQUE URI template: %w", err)
	}
	templateURL, err := url.Parse(expandedTemplate)
	if err != nil || templateURL.Scheme != "https" || templateURL.Host == "" || templateURL.Path == "" || strings.Contains(templateURL.Path, "{") {
		return nil, fmt.Errorf("MASQUE URI template must be an absolute HTTPS URL with a path")
	}
	variables := template.Varnames()
	if !slices.Contains(variables, "target_host") || !slices.Contains(variables, "target_port") {
		return nil, fmt.Errorf("MASQUE URI template must declare target_host and target_port")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load MASQUE TLS certificate: %w", err)
	}
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: wgPort}
	gateway := &Gateway{
		proxy:      &masquego.Proxy{},
		template:   template,
		target:     target,
		secret:     secret,
		serverID:   serverID,
		maxClients: int64(maxClients),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(templateURL.Path, gateway.handle)
	gateway.server = &http3.Server{
		Addr:      addr,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}),
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       5 * time.Minute,
			KeepAlivePeriod:      30 * time.Second,
			EnableDatagrams:      true,
		},
		EnableDatagrams: true,
		Handler:         mux,
		MaxHeaderBytes:  httpx.MaxHeaderBytes,
		IdleTimeout:     5 * time.Minute,
		Logger:          slog.Default(),
	}
	return gateway, nil
}

func (g *Gateway) Serve() error {
	return g.server.ListenAndServe()
}

func (g *Gateway) Shutdown(ctx context.Context) error {
	proxyErr := g.proxy.Close()
	serverErr := g.server.Shutdown(ctx)
	return errors.Join(proxyErr, serverErr)
}

func (g *Gateway) handle(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		http.Error(w, "tunnel authentication required", http.StatusUnauthorized)
		return
	}
	claims, ok := proxytoken.ValidateTunnel(strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")), g.secret)
	if !ok || claims.ServerID != g.serverID {
		http.Error(w, "invalid tunnel credential", http.StatusUnauthorized)
		return
	}
	request, err := masquego.ParseProxyRequest(r, g.template)
	if err != nil {
		var parseErr *masquego.ProxyRequestParseError
		if errors.As(err, &parseErr) {
			http.Error(w, "invalid CONNECT-UDP request", parseErr.HTTPStatus)
			return
		}
		http.Error(w, "invalid CONNECT-UDP request", http.StatusBadRequest)
		return
	}
	if !targetMatches(request.Target, g.target) {
		http.Error(w, "CONNECT-UDP target is not allowed", http.StatusForbidden)
		return
	}
	if g.active.Add(1) > g.maxClients {
		g.active.Add(-1)
		http.Error(w, "tunnel capacity reached", http.StatusTooManyRequests)
		return
	}
	defer g.active.Add(-1)

	conn, err := net.DialUDP("udp", nil, g.target)
	if err != nil {
		http.Error(w, "wireguard unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if err := g.proxy.ProxyConnectedSocket(w, request, conn); err != nil && r.Context().Err() == nil {
		slog.Warn("MASQUE session ended", "error", err, "remote", r.RemoteAddr)
	}
}

func targetMatches(target string, allowed *net.UDPAddr) bool {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port != allowed.Port {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.Equal(allowed.IP)
}

package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/httpx"
	"github.com/goastian/midori-vpn-core/internal/proxytoken"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

// Server implements an HTTP CONNECT forward proxy with short-lived proxy tokens.
type Server struct {
	cfg  *config.Config
	addr string

	// Optional DB pool for exit-node lookup
	pool *pgxpool.Pool

	// Per-user concurrency limiter
	mu        sync.Mutex
	active    map[string]int
	maxConns  int
	resolver  ipResolver
	dialer    contextDialer
	verifier  *proxytoken.Verifier
	serverID  uuid.UUID
	clusterID uuid.UUID
}

type ipResolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

var (
	errInvalidTarget   = errors.New("invalid proxy target")
	errForbiddenTarget = errors.New("forbidden proxy target")
)

// New creates a new proxy server.
func New(cfg *config.Config, verifier *proxytoken.Verifier) *Server {
	serverID, _ := uuid.Parse(cfg.ProxyServerID)
	clusterID, _ := uuid.Parse(cfg.TransportClusterID)
	return &Server{
		cfg:       cfg,
		addr:      fmt.Sprintf(":%d", cfg.ProxyPort),
		active:    make(map[string]int),
		maxConns:  cfg.ProxyMaxConnsPerUser,
		resolver:  net.DefaultResolver,
		dialer:    &net.Dialer{Timeout: 10 * time.Second},
		verifier:  verifier,
		serverID:  serverID,
		clusterID: clusterID,
	}
}

// NewWithDB creates a proxy server that can chain connections through a user's
// selected exit node when one is configured in the database.
func NewWithDB(cfg *config.Config, pool *pgxpool.Pool, verifier *proxytoken.Verifier) *Server {
	s := New(cfg, verifier)
	s.pool = pool
	return s
}

// Start listens and serves until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	srv := httpx.NewTunnelServer(s.addr, s)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	if s.cfg.ProxyTLSEnabled || (s.cfg.ProxyTLSCert != "" && s.cfg.ProxyTLSKey != "") {
		slog.Info("HTTPS CONNECT proxy (TLS) listening", "addr", s.addr, "cert", s.cfg.ProxyTLSCert)
		if err := srv.ListenAndServeTLS(s.cfg.ProxyTLSCert, s.cfg.ProxyTLSKey); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("secure proxy server: %w", err)
		}
		return nil
	}

	slog.Info("HTTP CONNECT proxy listening", "addr", s.addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("proxy server: %w", err)
	}
	return nil
}

// ServeHTTP handles all incoming requests. Only CONNECT is supported.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT is supported", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate via Proxy-Authorization: Bearer <proxy token> or Basic.
	sub, err := s.authenticate(r)
	if err != nil {
		slog.Info("proxy authentication rejected")
		w.Header().Set("Proxy-Authenticate", `Basic realm="midorivpn"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	// Per-user concurrency limit
	if !s.acquireSlot(sub) {
		slog.Warn("proxy concurrency limit hit")
		http.Error(w, "too many concurrent connections", http.StatusTooManyRequests)
		return
	}
	defer s.releaseSlot(sub)

	// Validate target: must be host:port
	_, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "invalid target address", http.StatusBadRequest)
		return
	}

	if parsedPort, parseErr := strconv.Atoi(port); parseErr != nil || parsedPort < 1 || parsedPort > 65535 {
		http.Error(w, "invalid target address", http.StatusBadRequest)
		return
	}

	// Dial the target (or chain through exit node if configured)
	targetConn, err := s.dialTarget(r.Context(), sub, r.Host)
	if err != nil {
		switch {
		case errors.Is(err, errInvalidTarget):
			http.Error(w, "invalid target address", http.StatusBadRequest)
		case errors.Is(err, errForbiddenTarget):
			slog.Warn("proxy target rejected by SSRF policy")
			http.Error(w, "forbidden target", http.StatusForbidden)
		default:
			slog.Warn("proxy target unavailable")
			http.Error(w, "failed to connect to target", http.StatusBadGateway)
		}
		return
	}
	defer targetConn.Close()

	// Enforce a hard maximum tunnel lifetime (2 hours) to prevent indefinite
	// resource exhaustion. Both sides get a deadline; hitting it closes the tunnel.
	const maxTunnelDuration = 2 * time.Hour
	deadline := time.Now().Add(maxTunnelDuration)
	targetConn.SetDeadline(deadline)

	slog.Info("proxy tunnel established")

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		slog.Error("proxy hijack failed", "error", err)
		return
	}
	defer clientConn.Close()
	clientConn.SetDeadline(deadline)

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	tunnelStart := time.Now()

	// Bidirectional copy: use sync.Once to close both sides when either
	// direction finishes, then wait for both goroutines to complete so that
	// byte counts from both directions are accurately captured.
	var (
		wg        sync.WaitGroup
		bytesUp   int64
		bytesDown int64
		closeOnce sync.Once
	)
	closeAll := func() {
		closeOnce.Do(func() {
			targetConn.Close()
			clientConn.Close()
		})
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer closeAll()
		bytesUp, _ = io.Copy(targetConn, clientConn)
	}()
	go func() {
		defer wg.Done()
		defer closeAll()
		bytesDown, _ = io.Copy(clientConn, targetConn)
	}()

	wg.Wait()

	slog.Info("proxy tunnel closed",
		"duration_s", int(time.Since(tunnelStart).Seconds()),
		"bytes_up", bytesUp,
		"bytes_down", bytesDown,
	)
}

// dialTarget opens a TCP connection to target, optionally chaining through
// the user's selected exit-node proxy (CONNECT-over-CONNECT).
func (s *Server) dialTarget(ctx context.Context, sub string, target string) (net.Conn, error) {
	validatedTargets, err := s.resolvePublicTargets(ctx, target)
	if err != nil {
		return nil, err
	}
	if s.pool != nil {
		userUUID, err := uuid.Parse(sub)
		if err == nil {
			exitRepo := repo.NewExitNodeRepo(s.pool)
			sel, err := exitRepo.GetUserExitNode(ctx, userUUID)
			if err == nil && sel != nil && sel.MeshIP != "" && sel.ProxyPort > 0 && sel.ProxyScheme == "http-connect" {
				for _, validatedTarget := range validatedTargets {
					if conn, dialErr := dialViaProxy(sel.MeshIP, sel.ProxyPort, validatedTarget); dialErr == nil {
						return conn, nil
					}
				}
				return nil, fmt.Errorf("dial selected exit proxy target")
			}
		}
	}
	for _, validatedTarget := range validatedTargets {
		conn, dialErr := s.dialer.DialContext(ctx, "tcp", validatedTarget)
		if dialErr == nil {
			return conn, nil
		}
	}
	return nil, fmt.Errorf("dial public target")
}

// dialViaProxy chains an HTTP CONNECT through an upstream proxy at host:port
// to reach target.
func dialViaProxy(proxyHost string, proxyPort int, target string) (net.Conn, error) {
	proxyAddr := net.JoinHostPort(proxyHost, strconv.Itoa(proxyPort))
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial exit proxy %s: %w", proxyAddr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set exit proxy handshake deadline: %w", err)
	}

	// Send CONNECT request to upstream proxy (no auth — mesh-internal)
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT to exit proxy: %w", err)
	}

	// Read response: must be "HTTP/1.1 200 ..."
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response from exit proxy: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("exit proxy CONNECT failed with status %d", resp.StatusCode)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("clear exit proxy handshake deadline: %w", err)
	}

	slog.Info("proxy tunnel chained through selected exit node")
	return conn, nil
}

// authenticate extracts and validates the proxy-scoped token from Proxy-Authorization.
// Accepts both "Bearer <token>" and "Basic <base64>" where the password is the token
// (the latter is required for Chrome extension compatibility via onAuthRequired).
func (s *Server) authenticate(r *http.Request) (string, error) {
	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		return "", fmt.Errorf("missing Proxy-Authorization header")
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid Proxy-Authorization format")
	}

	var tokenStr string
	switch {
	case strings.EqualFold(parts[0], "bearer"):
		tokenStr = parts[1]
	case strings.EqualFold(parts[0], "basic"):
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("invalid basic auth encoding: %w", err)
		}
		// Format: "user:transport_token" — extract the part after the first ':'.
		colonIdx := strings.IndexByte(string(decoded), ':')
		if colonIdx < 0 {
			return "", fmt.Errorf("invalid basic auth format")
		}
		tokenStr = string(decoded[colonIdx+1:])
		if tokenStr == "" {
			return "", fmt.Errorf("empty token in basic auth")
		}
	default:
		return "", fmt.Errorf("unsupported auth scheme: %s", parts[0])
	}

	claims, err := s.verifier.Verify(tokenStr, proxytoken.AudienceVPNProxy, s.serverID, s.clusterID)
	if err == nil {
		return claims.UserID.String(), nil
	}
	return "", fmt.Errorf("invalid or expired proxy-scoped token")
}

func (s *Server) acquireSlot(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[sub] >= s.maxConns {
		return false
	}
	s.active[sub]++
	return true
}

func (s *Server) releaseSlot(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active[sub]--
	if s.active[sub] <= 0 {
		delete(s.active, sub)
	}
}

func (s *Server) resolvePublicTargets(ctx context.Context, target string) ([]string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("%w: address", errInvalidTarget)
	}
	if parsedPort, parseErr := strconv.Atoi(port); parseErr != nil || parsedPort < 1 || parsedPort > 65535 {
		return nil, fmt.Errorf("%w: port", errInvalidTarget)
	}
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "localhost" || strings.HasSuffix(lower, ".local") {
		return nil, errForbiddenTarget
	}
	var ips []net.IP
	if literal := net.ParseIP(host); literal != nil {
		ips = []net.IP{literal}
	} else {
		ips, err = s.resolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("target resolution failed")
		}
	}
	validated := make([]string, 0, len(ips))
	for _, ip := range ips {
		if isForbiddenProxyIP(ip) {
			// Mixed public/private DNS is rejected as a whole. Filtering only the
			// private answer would allow an attacker to change answer ordering.
			return nil, errForbiddenTarget
		}
		validated = append(validated, net.JoinHostPort(ip.String(), port))
	}
	return validated, nil
}

var forbiddenProxyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func isForbiddenProxyIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	for _, prefix := range forbiddenProxyPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

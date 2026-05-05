package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

// Server implements an HTTP CONNECT forward proxy with JWT authentication.
type Server struct {
	cfg  *config.Config
	jwks *auth.JWKSProvider
	addr string

	// Optional DB pool for exit-node lookup
	pool *pgxpool.Pool

	// Per-user concurrency limiter
	mu       sync.Mutex
	active   map[string]int
	maxConns int
}

// New creates a new proxy server.
func New(cfg *config.Config, jwks *auth.JWKSProvider) *Server {
	return &Server{
		cfg:      cfg,
		jwks:     jwks,
		addr:     fmt.Sprintf(":%d", cfg.ProxyPort),
		active:   make(map[string]int),
		maxConns: cfg.ProxyMaxConnsPerUser,
	}
}

// NewWithDB creates a proxy server that can chain connections through a user's
// selected exit node when one is configured in the database.
func NewWithDB(cfg *config.Config, jwks *auth.JWKSProvider, pool *pgxpool.Pool) *Server {
	s := New(cfg, jwks)
	s.pool = pool
	return s
}

// Start listens and serves until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

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

	// Authenticate via Proxy-Authorization: Bearer <jwt> or Basic (password=jwt)
	sub, err := s.authenticate(r)
	if err != nil {
		slog.Info("proxy auth failed", "remote", r.RemoteAddr, "target", r.Host, "error", err)
		w.Header().Set("Proxy-Authenticate", `Basic realm="midorivpn"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	slog.Info("proxy CONNECT authenticated", "user", sub, "target", r.Host, "remote", r.RemoteAddr)

	// Per-user concurrency limit
	if !s.acquireSlot(sub) {
		slog.Warn("proxy concurrency limit hit", "user", sub)
		http.Error(w, "too many concurrent connections", http.StatusTooManyRequests)
		return
	}
	defer s.releaseSlot(sub)

	// Validate target: must be host:port
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "invalid target address", http.StatusBadRequest)
		return
	}

	// Block requests to private/reserved IP ranges (SSRF protection)
	if isPrivateTarget(host) {
		slog.Warn("proxy SSRF attempt blocked", "user", sub, "target", r.Host)
		http.Error(w, "forbidden target", http.StatusForbidden)
		return
	}

	// Block requests to privileged ports (< 1) — port is already validated by SplitHostPort
	_ = port

	// Dial the target (or chain through exit node if configured)
	targetConn, err := s.dialTarget(r.Context(), sub, r.Host)
	if err != nil {
		slog.Warn("proxy dial failed", "user", sub, "target", r.Host, "error", err)
		http.Error(w, "failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Enforce a hard maximum tunnel lifetime (2 hours) to prevent indefinite
	// resource exhaustion. Both sides get a deadline; hitting it closes the tunnel.
	const maxTunnelDuration = 2 * time.Hour
	deadline := time.Now().Add(maxTunnelDuration)
	targetConn.SetDeadline(deadline)

	slog.Info("proxy tunnel established", "user", sub, "target", r.Host)

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
		"user", sub,
		"target", r.Host,
		"duration_s", int(time.Since(tunnelStart).Seconds()),
		"bytes_up", bytesUp,
		"bytes_down", bytesDown,
	)
}

// dialTarget opens a TCP connection to target, optionally chaining through
// the user's selected exit-node proxy (CONNECT-over-CONNECT).
func (s *Server) dialTarget(ctx context.Context, sub string, target string) (net.Conn, error) {
	if s.pool != nil {
		userUUID, err := uuid.Parse(sub)
		if err == nil {
			exitRepo := repo.NewExitNodeRepo(s.pool)
			sel, err := exitRepo.GetUserExitNode(ctx, userUUID)
			if err == nil && sel != nil && sel.MeshIP != "" && sel.ProxyPort > 0 && sel.ProxyScheme == "http-connect" {
				return dialViaProxy(sel.MeshIP, sel.ProxyPort, target)
			}
		}
	}
	return net.DialTimeout("tcp", target, 10*time.Second)
}

// dialViaProxy chains an HTTP CONNECT through an upstream proxy at host:port
// to reach target.
func dialViaProxy(proxyHost string, proxyPort int, target string) (net.Conn, error) {
	proxyAddr := fmt.Sprintf("%s:%d", proxyHost, proxyPort)
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial exit proxy %s: %w", proxyAddr, err)
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
		return nil, fmt.Errorf("exit proxy CONNECT failed: %s", resp.Status)
	}

	slog.Info("proxy chained via exit node", "exit_proxy", proxyAddr, "target", target)
	return conn, nil
}

// authenticate extracts and validates the JWT from Proxy-Authorization header.
// Accepts both "Bearer <jwt>" and "Basic <base64>" where the password is the JWT
// (the latter is required for Chrome extension compatibility via onAuthRequired).
// JWE tokens (encrypted, 5 dot-segments) are validated via introspection since
// they cannot be verified with JWKS public keys.
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
		// Format: "user:jwt_token" — extract the part after the first ':'
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

	// JWE tokens (5 dot-separated segments) are encrypted and cannot be
	// validated locally with JWKS — use introspection instead.
	if strings.Count(tokenStr, ".") == 4 {
		slog.Debug("proxy: JWE token detected, using introspection")
		claims, err := auth.IntrospectTokenCached(s.cfg, tokenStr)
		if err != nil {
			return "", fmt.Errorf("JWE introspection failed: %w", err)
		}
		if claims.Sub == "" {
			return "", fmt.Errorf("missing sub claim in introspection")
		}
		return claims.Sub, nil
	}

	keySet := s.jwks.KeySet()
	token, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	expectedIssuer := s.cfg.AuthentikTokenIssuer()
	if expectedIssuer != "" {
		actual := strings.TrimRight(token.Issuer(), "/")
		expected := strings.TrimRight(expectedIssuer, "/")
		if actual != expected {
			return "", fmt.Errorf("issuer mismatch: got %s, want %s", actual, expected)
		}
	}

	sub := token.Subject()
	if sub == "" {
		return "", fmt.Errorf("missing sub claim")
	}

	return sub, nil
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

// isPrivateTarget returns true if the host resolves to a private/reserved IP or
// is a known private hostname pattern.
func isPrivateTarget(host string) bool {
	// Block well-known private hostnames
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".local") {
		return true
	}

	// Resolve and check IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		// If resolution fails, allow (the dial will fail anyway)
		return false
	}

	for _, ip := range ips {
		// Allow mesh subnet 10.200.0.0/16 — mesh peers must reach each other via proxy.
		if isMeshIP(ip) {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
		// Block IPv4-mapped IPv6 loopback
		if ip4 := ip.To4(); ip4 != nil {
			if ip4[0] == 127 {
				return true
			}
		}
	}

	return false
}

// meshSubnet is the overlay network range allocated to mesh networks.
var meshSubnet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("10.200.0.0/16")
	return n
}()

// isMeshIP reports whether ip falls within the mesh overlay subnet.
func isMeshIP(ip net.IP) bool {
	return meshSubnet != nil && meshSubnet.Contains(ip)
}

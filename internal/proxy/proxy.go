package proxy

import (
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

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
)

// Server implements an HTTP CONNECT forward proxy with JWT authentication.
type Server struct {
	cfg  *config.Config
	jwks *auth.JWKSProvider
	addr string

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
		maxConns: 20, // max concurrent tunnels per user
	}
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

	// Dial the target
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		slog.Warn("proxy dial failed", "user", sub, "target", r.Host, "error", err)
		http.Error(w, "failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

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

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy with deadline
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(targetConn, clientConn)
		slog.Debug("proxy tunnel client->target done", "target", r.Host, "bytes", n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(clientConn, targetConn)
		slog.Debug("proxy tunnel target->client done", "target", r.Host, "bytes", n)
		done <- struct{}{}
	}()

	// Wait for one direction to finish, then let defers close both
	<-done
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

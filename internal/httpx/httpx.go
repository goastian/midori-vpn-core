// Package httpx centralizes bounded HTTP clients, servers, and remote response
// reads used by MidoriVPN's network-facing components.
package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	MaxHeaderBytes   = 64 << 10
	MaxResponseBytes = 1 << 20

	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 90 * time.Second
)

var ErrResponseTooLarge = errors.New("remote response exceeds configured limit")

// ReadBody reads at most limit bytes and returns ErrResponseTooLarge instead
// of silently accepting a truncated response.
func ReadBody(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("negative response limit")
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

// NewClient returns an independent client and transport with bounded dialing,
// TLS negotiation, response headers, and idle connections. A non-zero timeout
// also bounds the total request duration.
func NewClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            dialer.DialContext,
			ForceAttemptHTTP2:      true,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:           64,
			MaxIdleConnsPerHost:    8,
			MaxConnsPerHost:        16,
			MaxResponseHeaderBytes: MaxHeaderBytes,
			IdleConnTimeout:        90 * time.Second,
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  10 * time.Second,
			ExpectContinueTimeout:  time.Second,
		},
	}
}

// NewClientWithAdditionalCA returns a bounded client whose TLS trust adds one
// operator-managed PEM bundle to the host roots. The private management CA is
// scoped to this client and never changes process-wide trust.
func NewClientWithAdditionalCA(timeout time.Duration, caPath string) (*http.Client, error) {
	client := NewClient(timeout)
	if caPath == "" {
		return client, nil
	}
	info, err := os.Lstat(caPath)
	if err != nil {
		return nil, fmt.Errorf("inspect additional CA: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxResponseBytes {
		return nil, errors.New("additional CA must be a non-empty regular file no larger than 1 MiB")
	}
	pemData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read additional CA: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pemData) {
		return nil, errors.New("additional CA contains no valid certificates")
	}
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.RootCAs = roots
	transport.TLSClientConfig.MinVersion = tls.VersionTLS13
	return client, nil
}

// NewAPIServer returns a server suitable for bounded request/response APIs.
func NewAPIServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
	}
}

// NewTunnelServer bounds CONNECT request headers and idle HTTP connections.
// ReadTimeout and WriteTimeout intentionally remain zero because, after
// hijacking, a tunnel can legitimately carry traffic for an arbitrary period.
func NewTunnelServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
	}
}

// AllowStreaming clears server-level request deadlines immediately before a
// handler upgrades to WebSocket or another explicitly long-lived stream.
func AllowStreaming(w http.ResponseWriter) {
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Time{})
	_ = controller.SetWriteDeadline(time.Time{})
}

// RemoteError carries only bounded operational metadata in Error(). The
// underlying cause remains available to errors.Is/As but is never formatted,
// preventing provider-controlled messages from entering logs accidentally.
type RemoteError struct {
	Operation     string
	Code          string
	Status        int
	ResponseBytes int
	cause         error
}

func NewRemoteError(operation, code string, status, responseBytes int, cause error) *RemoteError {
	return &RemoteError{
		Operation:     operation,
		Code:          code,
		Status:        status,
		ResponseBytes: responseBytes,
		cause:         cause,
	}
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("remote operation %s failed (%s, status=%d, response_bytes=%d)", e.Operation, e.Code, e.Status, e.ResponseBytes)
}

func (e *RemoteError) Unwrap() error {
	return e.cause
}

package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/nodeauth"
)

// ---------------------------------------------------------------------------
// Core HTTP client with retry (3 attempts) and circuit breaker
// ---------------------------------------------------------------------------

const (
	coreMaxRetries     = 3
	coreRetryBaseDelay = 500 * time.Millisecond
	coreRequestTimeout = 10 * time.Second
	cbFailureThreshold = 5
	cbResetTimeout     = 30 * time.Second
)

var (
	coreHTTP              = &http.Client{Timeout: coreRequestTimeout}
	coreAllowInsecureHTTP bool
	coreAllowedHosts      map[string]bool
	coreSigner            *nodeauth.Signer
)

func InitCoreSigningIdentity(nodeID, encodedPrivateKey string) error {
	signer, err := nodeauth.NewSigner(nodeID, encodedPrivateKey)
	if err != nil {
		return err
	}
	coreSigner = signer
	return nil
}

// InitCoreClient configures the core HTTP client with TLS settings.
func InitCoreClient(skipVerify bool, allowInsecureHTTP bool, allowedHosts string) {
	coreAllowInsecureHTTP = allowInsecureHTTP
	coreHTTP = &http.Client{
		Timeout: coreRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			MaxConnsPerHost:     20,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
		},
	}

	// Parse allowed hosts whitelist
	coreAllowedHosts = make(map[string]bool)
	for _, h := range strings.Split(allowedHosts, ",") {
		h = normalizeCoreAllowedHost(h)
		if h != "" {
			coreAllowedHosts[h] = true
		}
	}
}

func normalizeCoreAllowedHost(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" {
		return ""
	}
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(strings.Trim(host, "[]"))
	}
	return strings.ToLower(h)
}

// coreURL builds the full core API URL from server host/port.
// Behavior:
// 1) If host already includes http:// or https://, that scheme is respected.
// 2) Otherwise HTTPS is the default.
// 3) For local/test environments, CORE_ALLOW_INSECURE_HTTP=true allows HTTP.
func coreURL(server *models.VPNServer, path string) (string, string, error) {
	hostInput := strings.TrimSpace(server.Host)
	if hostInput == "" {
		return "", "", fmt.Errorf("empty core host")
	}

	var (
		scheme string
		host   string
		port   int
	)

	if strings.HasPrefix(hostInput, "http://") || strings.HasPrefix(hostInput, "https://") {
		u, err := url.Parse(hostInput)
		if err != nil {
			return "", "", fmt.Errorf("invalid core host URL %q: %w", hostInput, err)
		}
		if u.Host == "" {
			return "", "", fmt.Errorf("invalid core host URL %q: missing host", hostInput)
		}
		scheme = u.Scheme
		host = u.Hostname()
		if p := u.Port(); p != "" {
			parsed, err := strconv.Atoi(p)
			if err != nil {
				return "", "", fmt.Errorf("invalid core host URL %q: invalid port", hostInput)
			}
			port = parsed
		} else {
			port = server.Port
		}
	} else {
		host = hostInput
		port = server.Port
		scheme = "https"
		if coreAllowInsecureHTTP && port != 443 {
			scheme = "http"
		}
	}

	if port <= 0 {
		return "", "", fmt.Errorf("invalid core port %d", port)
	}
	host = strings.ToLower(host)

	// Validate host against whitelist
	if len(coreAllowedHosts) > 0 && !coreAllowedHosts[host] {
		return "", "", fmt.Errorf("core host %q not in allowed hosts whitelist", host)
	}

	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	base := fmt.Sprintf("%s://%s", scheme, hostPort)
	return base + path, hostPort, nil
}

// --- Circuit breaker (per server host) ---

type circuitState int

const (
	cbClosed circuitState = iota
	cbOpen
	cbHalfOpen
)

type circuitBreaker struct {
	mu           sync.Mutex
	state        circuitState
	failures     int
	lastFailedAt time.Time
}

var (
	cbMap   = make(map[string]*circuitBreaker)
	cbMapMu sync.Mutex
)

func getCB(host string) *circuitBreaker {
	cbMapMu.Lock()
	defer cbMapMu.Unlock()
	cb, ok := cbMap[host]
	if !ok {
		cb = &circuitBreaker{state: cbClosed}
		cbMap[host] = cb
	}
	return cb
}

func (cb *circuitBreaker) allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case cbClosed:
		return true
	case cbOpen:
		if time.Since(cb.lastFailedAt) > cbResetTimeout {
			cb.state = cbHalfOpen
			return true
		}
		return false
	case cbHalfOpen:
		return true
	}
	return false
}

func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = cbClosed
}

func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailedAt = time.Now()
	if cb.failures >= cbFailureThreshold {
		cb.state = cbOpen
	}
}

// --- Retry wrapper ---

func coreDoWithRetry(req *http.Request, bodyBytes []byte, host string) (*http.Response, error) {
	cb := getCB(host)

	var lastErr error
	for attempt := 0; attempt < coreMaxRetries; attempt++ {
		if !cb.allow() {
			return nil, fmt.Errorf("circuit breaker open for %s", host)
		}

		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
			req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
		}
		if coreSigner == nil {
			return nil, fmt.Errorf("control node signing identity is not initialized")
		}
		if err := coreSigner.Sign(req, bodyBytes); err != nil {
			return nil, fmt.Errorf("sign core request: %w", err)
		}

		resp, err := coreHTTP.Do(req)
		if err != nil {
			lastErr = err
			cb.recordFailure()
			slog.Error("core request failed", "attempt", attempt+1, "max_retries", coreMaxRetries, "host", host, "error", err)
			timer := time.NewTimer(coreRetryBaseDelay * time.Duration(attempt+1))
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-timer.C:
			}
			continue
		}

		if resp.StatusCode >= 500 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			lastErr = fmt.Errorf("core returned %d: %s", resp.StatusCode, string(body))
			cb.recordFailure()
			slog.Error("core request server error", "attempt", attempt+1, "max_retries", coreMaxRetries, "host", host, "status", resp.StatusCode)
			timer := time.NewTimer(coreRetryBaseDelay * time.Duration(attempt+1))
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-timer.C:
			}
			continue
		}

		cb.recordSuccess()
		return resp, nil
	}

	return nil, fmt.Errorf("core unreachable after %d retries: %w", coreMaxRetries, lastErr)
}

// --- Response types ---

type CoreAddPeerResponse struct {
	PublicKey   string `json:"public_key"`
	OperationID string `json:"operation_id"`
	AllowedIP   string `json:"allowed_ip"`
	Endpoint    string `json:"endpoint"`
}

type CorePeerStatsResponse struct {
	PublicKey     string `json:"public_key"`
	OperationID   string `json:"operation_id"`
	AllowedIP     string `json:"allowed_ip"`
	LastHandshake string `json:"last_handshake"`
	BytesSent     int64  `json:"tx_bytes"`
	BytesReceived int64  `json:"rx_bytes"`
}

type coreAPIResponse struct {
	OK   bool            `json:"ok"`
	Data json.RawMessage `json:"data"`
	Err  string          `json:"error"`
	Code string          `json:"code"`
}

type CoreAPIError struct {
	Status  int
	Code    string
	Message string
}

func (e *CoreAPIError) Error() string {
	return fmt.Sprintf("core returned %d (%s): %s", e.Status, e.Code, e.Message)
}

func parseCoreAPIError(status int, body []byte) error {
	var response coreAPIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return &CoreAPIError{Status: status, Code: "invalid_core_response", Message: "Core returned an invalid error response"}
	}
	code := response.Code
	if code == "" {
		code = "core_request_failed"
	}
	message := response.Err
	if message == "" {
		message = "Core request failed"
	}
	return &CoreAPIError{Status: status, Code: code, Message: message}
}

func coreErrorHasStatus(err error, status int) bool {
	var coreError *CoreAPIError
	return errors.As(err, &coreError) && coreError.Status == status
}

// --- Core API calls ---

func CallCoreAddPeer(server *models.VPNServer, pubkey, operationID string, presharedKey ...string) (*CoreAddPeerResponse, error) {
	return CallCoreAddPeerContext(context.Background(), server, pubkey, operationID, presharedKey...)
}

func CallCoreAddPeerContext(ctx context.Context, server *models.VPNServer, pubkey, operationID string, presharedKey ...string) (*CoreAddPeerResponse, error) {
	reqMap := map[string]interface{}{
		"public_key":   pubkey,
		"operation_id": operationID,
		"keepalive":    25,
	}
	if len(presharedKey) > 0 && presharedKey[0] != "" {
		reqMap["preshared_key"] = presharedKey[0]
	}
	payload, _ := json.Marshal(reqMap)

	fullURL, cbKey, err := coreURL(server, "/api/v1/peers")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := coreDoWithRetry(req, payload, cbKey)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, parseCoreAPIError(resp.StatusCode, body)
	}

	var apiResp coreAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("invalid core response: %s", string(body))
	}

	if !apiResp.OK {
		return nil, parseCoreAPIError(resp.StatusCode, body)
	}

	var result CoreAddPeerResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse core data: %w", err)
	}
	if result.OperationID != operationID {
		return nil, fmt.Errorf("core response operation_id %q does not match request", result.OperationID)
	}

	return &result, nil
}

func CallCoreRemovePeer(server *models.VPNServer, pubkey, expectedOperationID string) error {
	return CallCoreRemovePeerContext(context.Background(), server, pubkey, expectedOperationID)
}

func CallCoreRemovePeerContext(ctx context.Context, server *models.VPNServer, pubkey, expectedOperationID string) error {
	encodedKey := url.PathEscape(pubkey)
	fullURL, cbKey, err := coreURL(server, "/api/v1/peers/"+encodedKey)
	if err != nil {
		return err
	}

	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return err
	}
	query := parsedURL.Query()
	query.Set("expected_operation_id", expectedOperationID)
	parsedURL.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, parsedURL.String(), nil)
	if err != nil {
		return err
	}

	resp, err := coreDoWithRetry(req, nil, cbKey)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return parseCoreAPIError(resp.StatusCode, body)
	}

	return nil
}

// CallCoreRemoveCurrentPeer observes the operation currently owning a key and
// removes only that exact operation. A concurrent replacement turns the delete
// into a conflict instead of removing the replacement.
func CallCoreRemoveCurrentPeer(server *models.VPNServer, pubkey string) error {
	peer, err := CallCoreGetPeerStats(server, pubkey)
	if coreErrorHasStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if peer.OperationID == "" {
		return fmt.Errorf("core peer operation identity is unavailable")
	}
	return CallCoreRemovePeer(server, pubkey, peer.OperationID)
}

func CallCoreGetPeerStats(server *models.VPNServer, pubkey string) (*CorePeerStatsResponse, error) {
	return CallCoreGetPeerStatsContext(context.Background(), server, pubkey)
}

func CallCoreGetPeerStatsContext(ctx context.Context, server *models.VPNServer, pubkey string) (*CorePeerStatsResponse, error) {
	encodedKey := url.PathEscape(pubkey)
	fullURL, cbKey, err := coreURL(server, "/api/v1/peers/"+encodedKey+"/stats")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := coreDoWithRetry(req, nil, cbKey)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, parseCoreAPIError(resp.StatusCode, body)
	}

	var apiResp coreAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("invalid core response: %s", string(body))
	}
	if !apiResp.OK {
		return nil, parseCoreAPIError(resp.StatusCode, body)
	}

	var result CorePeerStatsResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse core stats: %w", err)
	}
	return &result, nil
}

// CoreServerStatsResponse mirrors wg.ServerStatsResponse from the core API.
type CoreServerStatsResponse struct {
	Interface  string `json:"interface"`
	PublicKey  string `json:"public_key"`
	ListenPort int    `json:"listen_port"`
	PeerCount  int    `json:"peer_count"`
	TotalTX    int64  `json:"total_tx_bytes"`
	TotalRX    int64  `json:"total_rx_bytes"`
}

// CallCoreServerStats fetches the WireGuard interface stats (including the real
// public key) from the core's GET /api/v1/stats endpoint.
func CallCoreServerStats(server *models.VPNServer) (*CoreServerStatsResponse, error) {
	fullURL, cbKey, err := coreURL(server, "/api/v1/stats")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := coreDoWithRetry(req, nil, cbKey)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, parseCoreAPIError(resp.StatusCode, body)
	}

	var apiResp coreAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("invalid core response: %s", string(body))
	}
	if !apiResp.OK {
		return nil, parseCoreAPIError(resp.StatusCode, body)
	}

	var result CoreServerStatsResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse core server stats: %w", err)
	}
	return &result, nil
}

func CallCoreListPeers(server *models.VPNServer) ([]CorePeerStatsResponse, error) {
	return CallCoreListPeersContext(context.Background(), server)
}

func CallCoreListPeersContext(ctx context.Context, server *models.VPNServer) ([]CorePeerStatsResponse, error) {
	fullURL, cbKey, err := coreURL(server, "/api/v1/peers")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := coreDoWithRetry(req, nil, cbKey)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, parseCoreAPIError(resp.StatusCode, body)
	}

	var apiResp coreAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("invalid core response: %s", string(body))
	}
	if !apiResp.OK {
		return nil, parseCoreAPIError(resp.StatusCode, body)
	}

	var result []CorePeerStatsResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse core peers: %w", err)
	}
	return result, nil
}

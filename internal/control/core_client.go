package control

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/goastian/midori-vpn-core/internal/models"
)

// ---------------------------------------------------------------------------
// Core HTTP client with retry (3 attempts) and circuit breaker
// ---------------------------------------------------------------------------

const (
	coreMaxRetries       = 3
	coreRetryBaseDelay   = 500 * time.Millisecond
	coreRequestTimeout   = 10 * time.Second
	cbFailureThreshold   = 5
	cbResetTimeout       = 30 * time.Second
)

var (
	coreHTTP = &http.Client{Timeout: coreRequestTimeout}
	coreTLSSkipVerify bool
)

// InitCoreClient configures the core HTTP client with TLS settings.
func InitCoreClient(skipVerify bool) {
	coreTLSSkipVerify = skipVerify
	coreHTTP = &http.Client{
		Timeout: coreRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
		},
	}
}

// coreScheme returns "https" if the server port is 443 or the host contains
// a scheme hint, otherwise "http". Servers can opt-in to TLS by setting
// their API port to 443 or by prefixing the host with "https://".
func coreScheme(server *models.VPNServer) string {
	if server.Port == 443 {
		return "https"
	}
	return "http"
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
		}

		resp, err := coreHTTP.Do(req)
		if err != nil {
			lastErr = err
			cb.recordFailure()
			log.Printf("core request attempt %d/%d to %s failed: %v", attempt+1, coreMaxRetries, host, err)
			time.Sleep(coreRetryBaseDelay * time.Duration(attempt+1))
			continue
		}

		if resp.StatusCode >= 500 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("core returned %d: %s", resp.StatusCode, string(body))
			cb.recordFailure()
			log.Printf("core request attempt %d/%d to %s: status %d", attempt+1, coreMaxRetries, host, resp.StatusCode)
			time.Sleep(coreRetryBaseDelay * time.Duration(attempt+1))
			continue
		}

		cb.recordSuccess()
		return resp, nil
	}

	return nil, fmt.Errorf("core unreachable after %d retries: %w", coreMaxRetries, lastErr)
}

// --- Response types ---

type CoreAddPeerResponse struct {
	PublicKey string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
	Endpoint  string `json:"endpoint"`
}

type CorePeerStatsResponse struct {
	PublicKey      string `json:"public_key"`
	AllowedIP     string `json:"allowed_ip"`
	LastHandshake string `json:"last_handshake"`
	BytesSent     int64  `json:"tx_bytes"`
	BytesReceived int64  `json:"rx_bytes"`
}

type coreAPIResponse struct {
	OK   bool            `json:"ok"`
	Data json.RawMessage `json:"data"`
	Err  string          `json:"error"`
}

// --- Core API calls ---

func CallCoreAddPeer(server *models.VPNServer, pubkey string) (*CoreAddPeerResponse, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"public_key": pubkey,
		"keepalive":  25,
	})

	coreURL := fmt.Sprintf("%s://%s:%d/api/v1/peers", coreScheme(server), server.Host, server.Port)
	req, err := http.NewRequest(http.MethodPost, coreURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Core-Token", server.CoreToken)

	resp, err := coreDoWithRetry(req, payload, server.Host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var apiResp coreAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("invalid core response: %s", string(body))
	}

	if !apiResp.OK {
		return nil, fmt.Errorf("core error: %s", apiResp.Err)
	}

	var result CoreAddPeerResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse core data: %w", err)
	}

	return &result, nil
}

func CallCoreRemovePeer(server *models.VPNServer, pubkey string) error {
	encodedKey := url.PathEscape(pubkey)
	coreURL := fmt.Sprintf("%s://%s:%d/api/v1/peers/%s", coreScheme(server), server.Host, server.Port, encodedKey)

	req, err := http.NewRequest(http.MethodDelete, coreURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Core-Token", server.CoreToken)

	resp, err := coreDoWithRetry(req, nil, server.Host)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("core returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func CallCoreGetPeerStats(server *models.VPNServer, pubkey string) (*CorePeerStatsResponse, error) {
	encodedKey := url.PathEscape(pubkey)
	coreURL := fmt.Sprintf("%s://%s:%d/api/v1/peers/%s/stats", coreScheme(server), server.Host, server.Port, encodedKey)

	req, err := http.NewRequest(http.MethodGet, coreURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Core-Token", server.CoreToken)

	resp, err := coreDoWithRetry(req, nil, server.Host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var apiResp coreAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("invalid core response: %s", string(body))
	}
	if !apiResp.OK {
		return nil, fmt.Errorf("core error: %s", apiResp.Err)
	}

	var result CorePeerStatsResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse core stats: %w", err)
	}
	return &result, nil
}

func CallCoreListPeers(server *models.VPNServer) ([]CorePeerStatsResponse, error) {
	coreURL := fmt.Sprintf("%s://%s:%d/api/v1/peers", coreScheme(server), server.Host, server.Port)

	req, err := http.NewRequest(http.MethodGet, coreURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Core-Token", server.CoreToken)

	resp, err := coreDoWithRetry(req, nil, server.Host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var apiResp coreAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("invalid core response: %s", string(body))
	}
	if !apiResp.OK {
		return nil, fmt.Errorf("core error: %s", apiResp.Err)
	}

	var result []CorePeerStatsResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse core peers: %w", err)
	}
	return result, nil
}

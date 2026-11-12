package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/httpx"
)

var introspectionHTTPClient = httpx.NewClient(10 * time.Second)

// IntrospectionClaims holds the claims returned by the Authentik introspection
// endpoint. Exported so other packages (e.g. proxy) can use introspection.
type IntrospectionClaims struct {
	Active bool          `json:"active"`
	Sub    string        `json:"sub"`
	Iss    string        `json:"iss"`
	Aud    tokenAudience `json:"aud"`
	Email  string        `json:"email"`
	Exp    int64         `json:"exp"`
	Groups interface{}   `json:"groups"`
}

func introspectionURLs(cfg *config.Config) []string {
	urls := make([]string, 0, 3)
	seen := make(map[string]struct{})

	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		urls = append(urls, u)
	}

	add(cfg.AuthentikIntrospectionURL())
	if appURL := cfg.AuthentikAppURL(); appURL != "" {
		add(appURL + "/introspect/")
	}
	if origin := cfg.AuthentikOrigin(); origin != "" {
		add(origin + "/application/o/introspect/")
	}

	return urls
}

func doIntrospectionRequest(ctx context.Context, endpoint string, form url.Values) (*IntrospectionClaims, int, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, 0, httpx.NewRemoteError("authentik_introspection", "request_build_failed", 0, 0, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := introspectionHTTPClient.Do(req)
	if err != nil {
		return nil, 0, 0, httpx.NewRemoteError("authentik_introspection", "transport_failed", 0, 0, err)
	}
	defer resp.Body.Close()

	body, err := httpx.ReadBody(resp.Body, httpx.MaxResponseBytes)
	if err != nil {
		size := 0
		code := "response_read_failed"
		if errors.Is(err, httpx.ErrResponseTooLarge) {
			size = httpx.MaxResponseBytes + 1
			code = "response_too_large"
		}
		return nil, resp.StatusCode, size, httpx.NewRemoteError("authentik_introspection", code, resp.StatusCode, size, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, len(body), httpx.NewRemoteError("authentik_introspection", "provider_rejected", resp.StatusCode, len(body), nil)
	}

	var claims IntrospectionClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, resp.StatusCode, len(body), httpx.NewRemoteError("authentik_introspection", "response_invalid", resp.StatusCode, len(body), err)
	}
	if !claims.Active {
		return nil, resp.StatusCode, len(body), httpx.NewRemoteError("authentik_introspection", "token_inactive", resp.StatusCode, len(body), nil)
	}
	if claims.Exp > 0 && time.Now().Unix() >= claims.Exp {
		return nil, resp.StatusCode, len(body), httpx.NewRemoteError("authentik_introspection", "token_expired", resp.StatusCode, len(body), nil)
	}

	return &claims, resp.StatusCode, len(body), nil
}

// IntrospectToken validates a token via the Authentik introspection endpoint.
func IntrospectToken(cfg *config.Config, token string) (*IntrospectionClaims, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	if cfg.AuthentikClientID == "" {
		return nil, fmt.Errorf("AUTHENTIK_CLIENT_ID is required for introspection")
	}
	if cfg.AuthentikClientSecret == "" {
		return nil, fmt.Errorf("AUTHENTIK_CLIENT_SECRET is required for introspection")
	}

	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", cfg.AuthentikClientID)
	form.Set("client_secret", cfg.AuthentikClientSecret)

	urls := introspectionURLs(cfg)
	if len(urls) == 0 {
		return nil, fmt.Errorf("no introspection URL configured")
	}

	var lastErr error
	allAttemptsFailed := true
	for i, endpoint := range urls {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		claims, status, responseBytes, err := doIntrospectionRequest(ctx, endpoint, form)
		cancel()

		if err == nil {
			if !audienceMatches(claims.Aud, cfg.AuthentikClientID) {
				return nil, errors.New("invalid token audience")
			}
			allAttemptsFailed = false
			slog.Debug("introspection success",
				"endpoint", endpoint,
				"attempt", i+1,
				"status", status,
				"active", claims.Active,
			)
			return claims, nil
		}

		errorCode := "introspection_failed"
		var remoteErr *httpx.RemoteError
		if errors.As(err, &remoteErr) {
			errorCode = remoteErr.Code
		}
		slog.Debug("introspection attempt failed",
			"operation", "authentik_introspection",
			"attempt", i+1,
			"status", status,
			"response_bytes", responseBytes,
			"code", errorCode,
		)
		lastErr = err

		// Retry next candidate on common endpoint/path mismatches.
		if status == http.StatusMethodNotAllowed || status == http.StatusNotFound {
			continue
		}
		// A provider rejection, malformed response or transport error is not
		// evidence of a different endpoint path. Never bypass that decision.
		break
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("introspection failed for all candidate endpoints")
	}
	if allAttemptsFailed {
		slog.Warn("introspection failed for all candidate endpoints", "operation", "authentik_introspection", "code", "all_candidates_failed")
	}
	return nil, lastErr
}

func introspectionGroups(value interface{}) []string {
	switch v := value.(type) {
	case []interface{}:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
		return groups
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return strings.Fields(v)
	default:
		return nil
	}
}

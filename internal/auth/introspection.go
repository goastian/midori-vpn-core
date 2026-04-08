package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
)

type introspectionClaims struct {
	Active bool        `json:"active"`
	Sub    string      `json:"sub"`
	Iss    string      `json:"iss"`
	Email  string      `json:"email"`
	Exp    int64       `json:"exp"`
	Groups interface{} `json:"groups"`
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

func doIntrospectionRequest(ctx context.Context, endpoint string, form url.Values) (*introspectionClaims, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, "", fmt.Errorf("read introspection response: %w", err)
	}

	bodyStr := string(body)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, bodyStr, fmt.Errorf("introspection returned %d: %s", resp.StatusCode, bodyStr)
	}

	var claims introspectionClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, resp.StatusCode, bodyStr, fmt.Errorf("parse introspection response: %w", err)
	}
	if !claims.Active {
		return nil, resp.StatusCode, bodyStr, fmt.Errorf("token is not active")
	}
	if claims.Exp > 0 && time.Now().Unix() >= claims.Exp {
		return nil, resp.StatusCode, bodyStr, fmt.Errorf("token expired")
	}

	return &claims, resp.StatusCode, bodyStr, nil
}

func introspectToken(cfg *config.Config, token string) (*introspectionClaims, error) {
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
	for i, endpoint := range urls {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		claims, status, body, err := doIntrospectionRequest(ctx, endpoint, form)
		cancel()

		if err == nil {
			slog.Debug("introspection success",
				"endpoint", endpoint,
				"attempt", i+1,
				"status", status,
				"active", claims.Active,
			)
			return claims, nil
		}

		bodyPreview := body
		if len(bodyPreview) > 240 {
			bodyPreview = bodyPreview[:240]
		}
		slog.Warn("introspection attempt failed",
			"endpoint", endpoint,
			"attempt", i+1,
			"status", status,
			"error", err,
			"body_preview", bodyPreview,
		)
		lastErr = err

		// Retry next candidate on common endpoint/path mismatches.
		if status == http.StatusMethodNotAllowed || status == http.StatusNotFound {
			continue
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("introspection failed for all candidate endpoints")
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

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.AuthentikIntrospectionURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read introspection response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection returned %d: %s", resp.StatusCode, string(body))
	}

	var claims introspectionClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("parse introspection response: %w", err)
	}
	if !claims.Active {
		return nil, fmt.Errorf("token is not active")
	}
	if claims.Exp > 0 && time.Now().Unix() >= claims.Exp {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
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

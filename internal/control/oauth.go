package control

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

type OAuthHandler struct {
	cfg            *config.Config
	allowedOrigins []string
}

func NewOAuthHandler(cfg *config.Config) *OAuthHandler {
	origins := make([]string, 0)
	for _, o := range strings.Split(cfg.CORSAllowedOrigins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			origins = append(origins, o)
		}
	}
	return &OAuthHandler{cfg: cfg, allowedOrigins: origins}
}

// csrfCheck validates Origin (or Referer) header against allowed origins.
// Returns true if the request passes; writes an error response and returns false otherwise.
func (h *OAuthHandler) csrfCheck(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Fallback to Referer
		if ref := r.Header.Get("Referer"); ref != "" {
			if parsed, err := url.Parse(ref); err == nil {
				origin = parsed.Scheme + "://" + parsed.Host
			}
		}
	}
	if origin == "" {
		respond.JsonError(w, "missing Origin header", http.StatusForbidden)
		return false
	}
	if !h.isAllowedOrigin(origin) {
		respond.JsonError(w, "origin not allowed", http.StatusForbidden)
		return false
	}
	return true
}

// isAllowedOrigin checks if the origin matches any of the configured CORS origins.
func (h *OAuthHandler) isAllowedOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	for _, allowed := range h.allowedOrigins {
		if allowed == origin {
			return true
		}
		// Support wildcard subdomains
		if strings.HasPrefix(allowed, "https://*.") || strings.HasPrefix(allowed, "http://*.") {
			suffix := allowed[strings.Index(allowed, "*.")+1:]
			scheme := allowed[:strings.Index(allowed, "://")]
			if parsed.Scheme == scheme && strings.HasSuffix(parsed.Host, suffix) {
				return true
			}
		}
	}
	return false
}

func (h *OAuthHandler) OIDCConfig(w http.ResponseWriter, r *http.Request) {
	slog.Info("[AUTH] OIDCConfig requested",
		"remote", r.RemoteAddr,
		"issuer", h.cfg.AuthentikTokenIssuer(),
		"authorization_url", h.cfg.AuthentikAuthorizationURL(),
		"token_url", h.cfg.AuthentikTokenURL(),
		"client_id", h.cfg.AuthentikClientID,
	)
	respond.JsonOK(w, map[string]string{
		"issuer":                 h.cfg.AuthentikTokenIssuer(),
		"authorization_endpoint": h.cfg.AuthentikAuthorizationURL(),
		"token_endpoint":         h.cfg.AuthentikTokenURL(),
		"userinfo_endpoint":      h.cfg.AuthentikUserInfoURL(),
		"end_session_endpoint":   h.cfg.AuthentikEndSessionURL(),
		"jwks_uri":               h.cfg.AuthentikJWKSURL,
		"client_id":              h.cfg.AuthentikClientID,
	}, http.StatusOK)
}

type CallbackRequest struct {
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *OAuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	slog.Info("[AUTH] Refresh hit", "remote", r.RemoteAddr)

	if !h.csrfCheck(w, r) {
		slog.Warn("[AUTH] Refresh CSRF check failed")
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("[AUTH] Refresh invalid request body", "error", err)
		respond.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.RefreshToken == "" {
		slog.Warn("[AUTH] Refresh missing refresh_token")
		respond.JsonError(w, "refresh_token is required", http.StatusBadRequest)
		return
	}

	tokenURL := h.cfg.AuthentikTokenURL()
	slog.Info("[AUTH] Refresh exchanging with Authentik", "token_url", tokenURL)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", req.RefreshToken)
	form.Set("client_id", h.cfg.AuthentikClientID)
	if h.cfg.AuthentikClientSecret != "" {
		form.Set("client_secret", h.cfg.AuthentikClientSecret)
	}

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		slog.Error("[AUTH] Refresh HTTP error", "error", err)
		respond.JsonError(w, "token refresh failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("[AUTH] Refresh failed to read response", "error", err)
		respond.JsonError(w, "failed to read token response", http.StatusBadGateway)
		return
	}

	slog.Info("[AUTH] Refresh Authentik response", "status", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		slog.Warn("[AUTH] Refresh Authentik returned error", "status", resp.StatusCode, "body", string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		slog.Error("[AUTH] Refresh failed to parse token", "error", err)
		respond.JsonError(w, "invalid token response", http.StatusBadGateway)
		return
	}

	slog.Info("[AUTH] Refresh SUCCESS")
	respond.JsonOK(w, tokenResp, http.StatusOK)
}

func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	slog.Info("[AUTH] Callback hit",
		"method", r.Method,
		"path", r.URL.Path,
		"remote", r.RemoteAddr,
		"origin", r.Header.Get("Origin"),
		"referer", r.Header.Get("Referer"),
	)

	if !h.csrfCheck(w, r) {
		slog.Warn("[AUTH] Callback CSRF check failed", "origin", r.Header.Get("Origin"), "referer", r.Header.Get("Referer"))
		return
	}

	var req CallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("[AUTH] Callback invalid request body", "error", err)
		respond.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	slog.Info("[AUTH] Callback parsed request",
		"code_length", len(req.Code),
		"redirect_uri", req.RedirectURI,
		"has_verifier", req.CodeVerifier != "",
	)

	if req.Code == "" || req.RedirectURI == "" {
		slog.Warn("[AUTH] Callback missing code or redirect_uri")
		respond.JsonError(w, "code and redirect_uri are required", http.StatusBadRequest)
		return
	}

	if !h.isAllowedRedirectURI(req.RedirectURI) {
		slog.Warn("[AUTH] Callback redirect_uri not allowed",
			"redirect_uri", req.RedirectURI,
			"allowed_origins", h.allowedOrigins,
		)
		respond.JsonError(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	tokenURL := h.cfg.AuthentikTokenURL()
	slog.Info("[AUTH] Callback exchanging code with Authentik",
		"token_url", tokenURL,
		"client_id", h.cfg.AuthentikClientID,
		"has_client_secret", h.cfg.AuthentikClientSecret != "",
	)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", req.Code)
	form.Set("redirect_uri", req.RedirectURI)
	form.Set("client_id", h.cfg.AuthentikClientID)
	if h.cfg.AuthentikClientSecret != "" {
		form.Set("client_secret", h.cfg.AuthentikClientSecret)
	}
	if req.CodeVerifier != "" {
		form.Set("code_verifier", req.CodeVerifier)
	}

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		slog.Error("[AUTH] Callback token exchange HTTP error", "error", err, "token_url", tokenURL)
		respond.JsonError(w, fmt.Sprintf("token exchange failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("[AUTH] Callback failed to read Authentik response", "error", err)
		respond.JsonError(w, "failed to read token response", http.StatusBadGateway)
		return
	}

	slog.Info("[AUTH] Callback Authentik response",
		"status", resp.StatusCode,
		"body_length", len(body),
	)

	if resp.StatusCode != http.StatusOK {
		slog.Warn("[AUTH] Callback Authentik returned error",
			"status", resp.StatusCode,
			"body", string(body),
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		slog.Error("[AUTH] Callback failed to parse token response", "error", err)
		respond.JsonError(w, "invalid token response", http.StatusBadGateway)
		return
	}

	slog.Info("[AUTH] Callback SUCCESS — tokens obtained",
		"has_access_token", tokenResp.AccessToken != "",
		"has_refresh_token", tokenResp.RefreshToken != "",
		"has_id_token", tokenResp.IDToken != "",
		"expires_in", tokenResp.ExpiresIn,
	)

	respond.JsonOK(w, tokenResp, http.StatusOK)
}

// isAllowedRedirectURI checks whether the redirect_uri origin matches
// one of the configured CORS allowed origins.
func (h *OAuthHandler) isAllowedRedirectURI(redirectURI string) bool {
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	origin := parsed.Scheme + "://" + parsed.Host
	return h.isAllowedOrigin(origin)
}

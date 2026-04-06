package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

type OAuthHandler struct {
	cfg *config.Config
}

func NewOAuthHandler(cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{cfg: cfg}
}

func (h *OAuthHandler) OIDCConfig(w http.ResponseWriter, r *http.Request) {
	respond.JsonOK(w, map[string]string{
		"issuer":                 h.cfg.AuthentikIssuer,
		"authorization_endpoint": h.cfg.AuthentikIssuer + "/authorize/",
		"token_endpoint":         h.cfg.AuthentikIssuer + "/token/",
		"userinfo_endpoint":      h.cfg.AuthentikIssuer + "/userinfo/",
		"end_session_endpoint":   h.cfg.AuthentikIssuer + "/end-session/",
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
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.RefreshToken == "" {
		respond.JsonError(w, "refresh_token is required", http.StatusBadRequest)
		return
	}

	tokenURL := h.cfg.AuthentikIssuer + "/token/"

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", req.RefreshToken)
	form.Set("client_id", h.cfg.AuthentikClientID)

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		respond.JsonError(w, "token refresh failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		respond.JsonError(w, "failed to read token response", http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		respond.JsonError(w, "invalid token response", http.StatusBadGateway)
		return
	}

	respond.JsonOK(w, tokenResp, http.StatusOK)
}

func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	var req CallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Code == "" || req.RedirectURI == "" {
		respond.JsonError(w, "code and redirect_uri are required", http.StatusBadRequest)
		return
	}

	if !h.isAllowedRedirectURI(req.RedirectURI) {
		respond.JsonError(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	tokenURL := h.cfg.AuthentikIssuer + "/token/"

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", req.Code)
	form.Set("redirect_uri", req.RedirectURI)
	form.Set("client_id", h.cfg.AuthentikClientID)
	if req.CodeVerifier != "" {
		form.Set("code_verifier", req.CodeVerifier)
	}

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		respond.JsonError(w, fmt.Sprintf("token exchange failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		respond.JsonError(w, "failed to read token response", http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
		return
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		respond.JsonError(w, "invalid token response", http.StatusBadGateway)
		return
	}

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

	for _, allowed := range strings.Split(h.cfg.CORSAllowedOrigins, ",") {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		// Support wildcard subdomains like https://*.astian.org
		if strings.HasPrefix(allowed, "https://*.") || strings.HasPrefix(allowed, "http://*.") {
			suffix := allowed[strings.Index(allowed, "*.")+1:]
			scheme := allowed[:strings.Index(allowed, "://")]
			if parsed.Scheme == scheme && strings.HasSuffix(parsed.Host, suffix) {
				return true
			}
		} else if origin == allowed {
			return true
		}
	}
	return false
}

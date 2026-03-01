package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/goastian/midori-vpn-core/internal/api"
	"github.com/goastian/midori-vpn-core/internal/config"
)

type OAuthHandler struct {
	cfg *config.Config
}

func NewOAuthHandler(cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{cfg: cfg}
}

func (h *OAuthHandler) OIDCConfig(w http.ResponseWriter, r *http.Request) {
	api.JsonOK(w, map[string]string{
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

func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	var req CallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Code == "" || req.RedirectURI == "" {
		api.JsonError(w, "code and redirect_uri are required", http.StatusBadRequest)
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
		api.JsonError(w, fmt.Sprintf("token exchange failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		api.JsonError(w, "failed to read token response", http.StatusBadGateway)
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
		api.JsonError(w, "invalid token response", http.StatusBadGateway)
		return
	}

	api.JsonOK(w, tokenResp, http.StatusOK)
}

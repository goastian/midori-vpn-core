package control

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

type OAuthHandler struct {
	cfg                     *config.Config
	allowedOrigins          []string
	allowedExtensionOrigins []string // nil means TOFU is active (DB-backed allow-list)
	trustedExt              *repo.TrustedExtensionRepo
}

func NewOAuthHandler(cfg *config.Config, trustedExt *repo.TrustedExtensionRepo) *OAuthHandler {
	origins := make([]string, 0)
	for _, o := range strings.Split(cfg.CORSAllowedOrigins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			origins = append(origins, o)
		}
	}

	var extOrigins []string
	for _, o := range strings.Split(cfg.AllowedExtensionOrigins, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			extOrigins = append(extOrigins, o)
		}
	}

	return &OAuthHandler{
		cfg:                     cfg,
		allowedOrigins:          origins,
		allowedExtensionOrigins: extOrigins,
		trustedExt:              trustedExt,
	}
}

// isExtensionOrigin reports whether origin is a browser-extension URL.
func isExtensionOrigin(origin string) bool {
	return strings.HasPrefix(origin, "moz-extension://") ||
		strings.HasPrefix(origin, "chrome-extension://")
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
	// Browser extensions have dynamic origin URLs.
	//
	// Resolution order:
	//   1. If ALLOWED_EXTENSION_ORIGINS is set, only those exact origins pass.
	//   2. Otherwise, fall back to TOFU: an origin is allowed if it has been
	//      previously registered (via a successful OAuth callback) and is not
	//      revoked.
	//   3. If neither list is available, the request is rejected.
	//
	// New origins become trusted via the Callback handler, which performs the
	// registration only after Authentik successfully exchanges the code.
	if isExtensionOrigin(origin) {
		if len(h.allowedExtensionOrigins) > 0 {
			for _, allowed := range h.allowedExtensionOrigins {
				if origin == allowed {
					return true
				}
			}
			slog.Warn("extension origin rejected: not in ALLOWED_EXTENSION_ORIGINS", "origin", origin)
			return false
		}
		if h.trustedExt != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			ok, err := h.trustedExt.IsTrusted(ctx, origin)
			if err != nil {
				slog.Error("trusted extension origin lookup failed", "origin", origin, "error", err)
				return false
			}
			if !ok {
				slog.Warn("extension origin rejected: not yet registered (TOFU)", "origin", origin)
			}
			return ok
		}
		slog.Warn("extension origin rejected: no allow-list and no TOFU repo", "origin", origin)
		return false
	}

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

	// Use context.Background so that a client disconnect does not abort the
	// token exchange mid-flight. The 15-second timeout still applies.
	tokenCtx, tokenCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer tokenCancel()
	tokenReq, err := http.NewRequestWithContext(tokenCtx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		slog.Error("[AUTH] Refresh failed to create request", "error", err)
		respond.JsonError(w, "token refresh failed", http.StatusInternalServerError)
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(tokenReq)
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

	// Read and parse the body first so we can inspect code_verifier before
	// deciding whether CSRF validation is needed.
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

	// When a code_verifier is present the client is using PKCE, which already
	// binds the token exchange to the original authorization request and
	// provides equivalent CSRF protection. Skip the Origin/Referer check so
	// browser-extension backgrounds (which have no Origin header) can call
	// this endpoint directly.
	if req.CodeVerifier == "" {
		if !h.csrfCheck(w, r) {
			slog.Warn("[AUTH] Callback CSRF check failed", "origin", r.Header.Get("Origin"), "referer", r.Header.Get("Referer"))
			return
		}
	}

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

	// Use context.Background so that a client disconnect does not abort the
	// token exchange mid-flight. The 15-second timeout still applies.
	tokenCtx, tokenCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer tokenCancel()
	tokenReq, err := http.NewRequestWithContext(tokenCtx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		slog.Error("[AUTH] Callback failed to create request", "error", err)
		respond.JsonError(w, "token exchange failed", http.StatusInternalServerError)
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		slog.Error("[AUTH] Callback token exchange HTTP error", "error", err, "token_url", tokenURL)
		respond.JsonError(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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

	// TOFU: register the requesting extension origin once Authentik confirmed
	// the authorization code. Only runs when ALLOWED_EXTENSION_ORIGINS is empty
	// (otherwise the static allow-list is authoritative). Failures here must
	// not block the response — the user has already authenticated.
	if h.trustedExt != nil && len(h.allowedExtensionOrigins) == 0 {
		if origin := r.Header.Get("Origin"); isExtensionOrigin(origin) {
			regCtx, regCancel := context.WithTimeout(context.Background(), 2*time.Second)
			if err := h.trustedExt.Register(regCtx, origin, nil); err != nil {
				slog.Warn("[AUTH] Callback failed to register trusted extension origin",
					"origin", origin, "error", err)
			} else {
				slog.Info("[AUTH] Callback registered trusted extension origin", "origin", origin)
			}
			regCancel()
		}
	}

	respond.JsonOK(w, tokenResp, http.StatusOK)
}

// isAllowedRedirectURI checks whether the redirect_uri is explicitly the
// configured extension callback URL, or its origin matches an allowed CORS
// origin. The explicit check ensures self-hosted deployments with a custom
// PUBLIC_BASE_URL that isn't in CORS_ALLOWED_ORIGINS still work.
func (h *OAuthHandler) isAllowedRedirectURI(redirectURI string) bool {
	if extCB := h.cfg.ExtensionCallbackURL(); extCB != "" && redirectURI == extCB {
		return true
	}
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	origin := parsed.Scheme + "://" + parsed.Host
	return h.isAllowedOrigin(origin)
}

// ExtensionCallback serves a minimal HTML page at the configured
// EXTENSION_CALLBACK_PATH. Authentik redirects the browser here after the
// user authenticates; the extension's background script detects the navigation
// via webNavigation.onCommitted and exchanges the code for tokens.
func (h *OAuthHandler) ExtensionCallback(w http.ResponseWriter, r *http.Request) {
	slog.Info("[AUTH] ExtensionCallback hit",
		"remote", r.RemoteAddr,
		"has_code", r.URL.Query().Get("code") != "",
	)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MidoriVPN \u2014 Sign-in</title>
  <style>
    :root { color-scheme: light dark; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
    body {
      margin: 0; min-height: 100vh;
      display: grid; place-items: center;
      background: #0f172a; color: #e2e8f0;
    }
    main {
      width: min(26rem, calc(100vw - 2rem));
      padding: 2rem; border-radius: 1rem;
      background: rgba(30,41,59,0.9);
      box-shadow: 0 24px 80px rgba(0,0,0,.45);
      text-align: center;
    }
    .icon { font-size: 3rem; margin-bottom: 1rem; }
    h1 { margin: 0 0 .5rem; font-size: 1.25rem; }
    p  { margin: 0; color: #94a3b8; line-height: 1.5; font-size: .9rem; }
  </style>
</head>
<body>
  <main>
    <div class="icon">&#x2713;</div>
    <h1>Authentication complete</h1>
    <p>You can return to the MidoriVPN extension.<br>This tab closes automatically.</p>
  </main>
  <script>
    // Fallback: close this tab if the extension background script did not
    // already close it within 3 seconds (e.g. extension not loaded).
    setTimeout(function() { try { window.close(); } catch(_) {} }, 3000);
  </script>
</body>
</html>`))
}

// LogoutRequest carries the token(s) to invalidate on logout.
type LogoutRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Logout invalidates the provided access token from the introspection cache so
// that it cannot be reused, even within its normal TTL window. It optionally
// also revokes the refresh token at the Authentik token revocation endpoint.
// The endpoint is idempotent: unknown or already-invalidated tokens return 200.
func (h *OAuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	slog.Info("[AUTH] Logout hit", "remote", r.RemoteAddr)

	if !h.csrfCheck(w, r) {
		slog.Warn("[AUTH] Logout CSRF check failed")
		return
	}

	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("[AUTH] Logout invalid request body", "error", err)
		respond.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Immediately evict the token from the local introspection cache.
	if req.AccessToken != "" {
		auth.InvalidateIntrospection(req.AccessToken)
		slog.Info("[AUTH] Logout access token evicted from introspection cache")
	}

	// Best-effort revocation at Authentik (refresh token).
	// Failures are logged but do not affect the 200 response — the local cache
	// invalidation above is sufficient for same-node protection.
	if req.RefreshToken != "" && h.cfg.AuthentikClientID != "" {
		go func() {
			revokeURL := strings.TrimRight(h.cfg.AuthentikIssuer, "/") + "/application/o/revoke-token/"
			form := url.Values{}
			form.Set("token", req.RefreshToken)
			form.Set("token_type_hint", "refresh_token")
			form.Set("client_id", h.cfg.AuthentikClientID)
			if h.cfg.AuthentikClientSecret != "" {
				form.Set("client_secret", h.cfg.AuthentikClientSecret)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			revokeReq, err := http.NewRequestWithContext(ctx, http.MethodPost, revokeURL, strings.NewReader(form.Encode()))
			if err != nil {
				slog.Warn("[AUTH] Logout failed to build revocation request", "error", err)
				return
			}
			revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := http.DefaultClient.Do(revokeReq)
			if err != nil {
				slog.Warn("[AUTH] Logout revocation request failed", "error", err)
				return
			}
			resp.Body.Close()
			slog.Info("[AUTH] Logout refresh token revocation", "status", resp.StatusCode)
		}()
	}

	respond.JsonOK(w, map[string]string{"status": "logged_out"}, http.StatusOK)
}

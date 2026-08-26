package config

import (
	"log"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/yosida95/uritemplate/v3"
)

type Config struct {
	// Application
	AppEnv string // "production" or "development"

	// HTTP
	Port string

	// Signed node-to-node HTTP authentication.
	ControlNodeID         string
	ControlNodePrivateKey string
	NodeAuthorizedKeys    string
	NodeRevokedIDs        string
	NodeAuthRedisURL      string

	// HMAC secret used only for short-lived proxy and WSS credentials.
	CredentialSigningSecret string

	// CORS
	CORSAllowedOrigins string // comma-separated list of allowed origins
	// Allowed browser-extension origins for CORS (comma-separated, e.g.
	// "chrome-extension://abcdef...,moz-extension://xxxxxxxx-...").
	// If empty, OAuth uses its database-backed trusted-origin registry.
	AllowedExtensionOrigins string
	PublicBaseURL           string // public base URL used to derive hosted callback URLs
	ExtensionCallbackPath   string // HTTP path for browser-extension OAuth callback page

	// WireGuard
	WGInterface string
	WGPort      int
	Subnet      string
	ConfigDir   string
	Endpoint    string

	// PostgreSQL
	DatabaseURL string

	// Redis
	RedisURL string

	// Authentik OIDC
	AuthentikIssuer                   string
	AuthentikClientID                 string
	AuthentikClientSecret             string
	AuthentikJWKSURL                  string
	AuthentikIntrospectionURLOverride string // optional: overrides derived introspection URL
	OAuthAllowedRedirectURIs          string // comma-separated exact redirect URIs for native clients
	ControlOAuthRedirectURI           string // exact hosted SPA redirect URI published by auth discovery

	// Core-to-core TLS
	CoreTLSSkipVerify bool   // skip TLS cert verification for self-signed certs
	CoreAllowHTTP     bool   // allow plain HTTP for local/testing inter-core calls
	CoreAllowedHosts  string // comma-separated whitelist of allowed core server hosts (empty = allow all)

	// Rate limiting
	RateLimitRPS   int // requests per second per IP (0 = disabled)
	RateLimitBurst int // burst size for rate limiter

	// Trusted reverse proxies (CIDR or IP)
	TrustedProxies string // comma-separated list of trusted proxy IPs/CIDRs (empty = trust all — NOT recommended for production)

	// Device limits
	MaxDevicesPerUser int // max active connections per user (0 = unlimited)

	// Per-user rate limit on the /connect endpoint
	ConnectRateLimitRPS   float64 // token-bucket refill rate in tokens/second (0 = disabled)
	ConnectRateLimitBurst int     // maximum burst size

	// VPN client configuration
	VpnDNS string // comma-separated DNS servers pushed to VPN clients

	// Shared client PKI for OpenVPN and IKEv2. Devices submit CSRs; the CA
	// private key signs certificates but never receives device private keys.
	VPNClientCACert       string
	VPNClientCAKey        string
	VPNClientCertTTLHours int
	VPNClientCRLURL       string

	// HTTP / HTTPS CONNECT proxy
	ProxyEnabled         bool   // enable the HTTP CONNECT forward proxy
	ProxyPort            int    // TCP port for the forward proxy (default 8443)
	ProxyMaxConnsPerUser int    // max concurrent CONNECT tunnels per user (default 20)
	ProxyTLSEnabled      bool   // enable direct TLS termination on the proxy port
	ProxyTLSTerminated   bool   // TLS is terminated by the trusted host Nginx proxy
	ProxyTLSCert         string // path to TLS certificate (fullchain.pem)
	ProxyTLSKey          string // path to TLS private key (privkey.pem)

	// Authenticated WireGuard-over-WebSocket relay. Disabled unless explicitly enabled.
	WSSTunnelEnabled    bool
	WSSTunnelServerID   string
	WSSTunnelMaxClients int

	// Authenticated WireGuard-over-MASQUE relay (RFC 9298 CONNECT-UDP).
	MasqueEnabled     bool
	MasquePort        int
	MasqueTLSCert     string
	MasqueTLSKey      string
	MasqueURITemplate string
	MasqueServerID    string
	MasqueMaxClients  int

	// WebSocket limits per plan
	WSMaxGlobal int // max global WS connections (0 = unlimited)
	WSMaxFree   int // max WS conns for free plan
	WSMaxBasic  int // max WS conns for basic plan
	WSMaxMedium int // max WS conns for medium plan
	WSMaxPro    int // max WS conns for pro plan
	WSMaxAdmin  int // max WS conns for admins

	// Astian Payment microservice integration
	AstianPaymentURL   string // base URL of the configured payment service
	AstianPaymentToken string // internal service token for API authentication
}

// wgInterfaceRe allows only safe characters for a WireGuard interface name.
// Linux netdev names are limited to 15 characters, alphanumeric plus - and _.
var wgInterfaceRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

func Load() *Config {
	issuer := strings.TrimRight(env("AUTHENTIK_ISSUER"), "/")

	jwksURL := env("AUTHENTIK_JWKS_URL")
	if jwksURL == "" && issuer != "" {
		jwksURL = strings.TrimRight(issuer, "/") + "/jwks/"
	}

	cfg := &Config{
		AppEnv:                  requireEnv("APP_ENV"),
		Port:                    requireEnv("VPN_CORE_PORT"),
		ControlNodeID:           env("CONTROL_NODE_ID"),
		ControlNodePrivateKey:   env("CONTROL_NODE_PRIVATE_KEY"),
		NodeAuthorizedKeys:      requireEnv("NODE_AUTHORIZED_KEYS"),
		NodeRevokedIDs:          env("NODE_REVOKED_IDS"),
		NodeAuthRedisURL:        env("NODE_AUTH_REDIS_URL"),
		CredentialSigningSecret: env("CREDENTIAL_SIGNING_SECRET"),
		WGInterface:             requireEnv("WG_INTERFACE"),
		WGPort:                  requireEnvInt("WG_PORT"),
		Subnet:                  requireEnv("WG_SUBNET"),
		ConfigDir:               requireEnv("WG_CONFIG_DIR"),
		Endpoint:                requireEnv("WG_ENDPOINT"),

		CORSAllowedOrigins:      requireEnv("CORS_ALLOWED_ORIGINS"),
		AllowedExtensionOrigins: env("ALLOWED_EXTENSION_ORIGINS"),
		PublicBaseURL:           strings.TrimRight(requireEnv("PUBLIC_BASE_URL"), "/"),
		ExtensionCallbackPath:   requireEnv("EXTENSION_CALLBACK_PATH"),

		DatabaseURL:                       databaseURLFromEnv(),
		RedisURL:                          redisURLFromEnv(),
		AuthentikIssuer:                   issuer,
		AuthentikClientID:                 env("AUTHENTIK_CLIENT_ID"),
		AuthentikClientSecret:             env("AUTHENTIK_CLIENT_SECRET"),
		AuthentikJWKSURL:                  jwksURL,
		AuthentikIntrospectionURLOverride: env("AUTHENTIK_INTROSPECTION_URL"),
		OAuthAllowedRedirectURIs:          env("OAUTH_ALLOWED_REDIRECT_URIS"),
		ControlOAuthRedirectURI:           env("CONTROL_OAUTH_REDIRECT_URI"),

		CoreTLSSkipVerify: requireEnvBool("CORE_TLS_SKIP_VERIFY"),
		CoreAllowHTTP:     requireEnvBool("CORE_ALLOW_INSECURE_HTTP"),
		CoreAllowedHosts:  env("CORE_ALLOWED_HOSTS"),

		RateLimitRPS:   requireEnvInt("RATE_LIMIT_RPS"),
		RateLimitBurst: requireEnvInt("RATE_LIMIT_BURST"),

		TrustedProxies: env("TRUSTED_PROXIES"),

		MaxDevicesPerUser: requireEnvInt("MAX_DEVICES_PER_USER"),

		ConnectRateLimitRPS:   requireEnvFloat("CONNECT_RATE_LIMIT_RPS"),
		ConnectRateLimitBurst: requireEnvInt("CONNECT_RATE_LIMIT_BURST"),

		VpnDNS: requireEnv("VPN_DNS"),

		VPNClientCACert:       env("VPN_CLIENT_CA_CERT"),
		VPNClientCAKey:        env("VPN_CLIENT_CA_KEY"),
		VPNClientCertTTLHours: envIntDefault("VPN_CLIENT_CERT_TTL_HOURS", 2160),
		VPNClientCRLURL:       env("VPN_CLIENT_CRL_URL"),

		ProxyEnabled:         requireEnvBool("PROXY_ENABLED"),
		ProxyPort:            requireEnvInt("PROXY_PORT"),
		ProxyMaxConnsPerUser: requireEnvInt("PROXY_MAX_CONNS_PER_USER"),
		ProxyTLSEnabled:      requireEnvBool("PROXY_TLS_ENABLED"),
		ProxyTLSTerminated:   requireEnvBool("PROXY_TLS_TERMINATED_BY_NGINX"),
		ProxyTLSCert:         env("PROXY_TLS_CERT"),
		ProxyTLSKey:          env("PROXY_TLS_KEY"),
		WSSTunnelEnabled:     requireEnvBool("WSS_TUNNEL_ENABLED"),
		WSSTunnelServerID:    env("WSS_TUNNEL_SERVER_ID"),
		WSSTunnelMaxClients:  requireEnvInt("WSS_TUNNEL_MAX_CLIENTS"),
		MasqueEnabled:        requireEnvBool("MASQUE_ENABLED"),
		MasquePort:           requireEnvInt("MASQUE_PORT"),
		MasqueTLSCert:        env("MASQUE_TLS_CERT"),
		MasqueTLSKey:         env("MASQUE_TLS_KEY"),
		MasqueURITemplate:    env("MASQUE_URI_TEMPLATE"),
		MasqueServerID:       env("MASQUE_SERVER_ID"),
		MasqueMaxClients:     requireEnvInt("MASQUE_MAX_CLIENTS"),

		WSMaxGlobal: requireEnvInt("WS_MAX_GLOBAL"),
		WSMaxFree:   requireEnvInt("WS_MAX_FREE"),
		WSMaxBasic:  requireEnvInt("WS_MAX_BASIC"),
		WSMaxMedium: requireEnvInt("WS_MAX_MEDIUM"),
		WSMaxPro:    requireEnvInt("WS_MAX_PRO"),
		WSMaxAdmin:  requireEnvInt("WS_MAX_ADMIN"),

		AstianPaymentURL:   strings.TrimRight(env("ASTIAN_PAYMENT_URL"), "/"),
		AstianPaymentToken: env("ASTIAN_PAYMENT_INTERNAL_TOKEN"),
	}

	if cfg.NodeAuthorizedKeys == "" {
		log.Fatal("FATAL: NODE_AUTHORIZED_KEYS must register at least one Ed25519 caller identity")
	}
	if cfg.AppEnv != "production" && cfg.AppEnv != "development" {
		log.Fatalf("FATAL: APP_ENV must be production or development, got %q", cfg.AppEnv)
	}
	port, err := strconv.Atoi(cfg.Port)
	if err != nil || port < 1 || port > 65535 {
		log.Fatalf("FATAL: VPN_CORE_PORT must be an integer between 1 and 65535, got %q", cfg.Port)
	}
	if cfg.AuthentikClientID != "" && (cfg.ControlNodeID == "" || cfg.ControlNodePrivateKey == "") {
		log.Fatal("FATAL: CONTROL_NODE_ID and CONTROL_NODE_PRIVATE_KEY are required when the Control API is enabled")
	}
	if cfg.AuthentikClientID != "" && (cfg.AuthentikIssuer == "" || cfg.OAuthAllowedRedirectURIs == "" || cfg.ControlOAuthRedirectURI == "") {
		log.Fatal("FATAL: AUTHENTIK_ISSUER, OAUTH_ALLOWED_REDIRECT_URIS and CONTROL_OAUTH_REDIRECT_URI are required when the Control API is enabled")
	}
	if cfg.AuthentikClientID != "" && (cfg.DatabaseURL == "" || cfg.RedisURL == "") {
		log.Fatal("FATAL: PostgreSQL and Redis must be configured when the Control API is enabled")
	}
	if (cfg.AuthentikClientID != "" || cfg.ProxyEnabled || cfg.WSSTunnelEnabled || cfg.MasqueEnabled) && cfg.CredentialSigningSecret == "" {
		log.Fatal("FATAL: CREDENTIAL_SIGNING_SECRET is required for scoped proxy and tunnel credentials")
	}
	if cfg.AppEnv == "production" && cfg.NodeAuthRedisURL == "" {
		log.Fatal("FATAL: NODE_AUTH_REDIS_URL is required in production for shared replay prevention and immediate revocation")
	}
	if (cfg.VPNClientCACert == "") != (cfg.VPNClientCAKey == "") {
		log.Fatal("FATAL: VPN_CLIENT_CA_CERT and VPN_CLIENT_CA_KEY must be configured together")
	}
	if cfg.VPNClientCACert != "" {
		if cfg.VPNClientCertTTLHours < 24 || cfg.VPNClientCertTTLHours > 8760 {
			log.Fatal("FATAL: VPN_CLIENT_CERT_TTL_HOURS must be between 24 and 8760")
		}
		if cfg.VPNClientCRLURL == "" {
			cfg.VPNClientCRLURL = cfg.PublicBaseURL + "/pki/client.crl"
		}
		if u, err := url.ParseRequestURI(cfg.VPNClientCRLURL); err != nil || u.Scheme != "https" || u.Host == "" {
			log.Fatal("FATAL: VPN_CLIENT_CRL_URL must be an absolute HTTPS URL")
		}
	}

	// Validate WireGuard interface name against a safe character set to prevent
	// path traversal when writing config files (e.g. ../../../etc/passwd).
	if !wgInterfaceRe.MatchString(cfg.WGInterface) {
		log.Fatalf("FATAL: WG_INTERFACE %q is not a valid interface name (only [a-zA-Z0-9_-]{1,15} allowed)", cfg.WGInterface)
	}

	// Validate Authentik URLs at startup so misconfiguration fails fast.
	if cfg.AuthentikIssuer != "" {
		if u, err := url.ParseRequestURI(cfg.AuthentikIssuer); err != nil || u.Host == "" {
			log.Fatalf("FATAL: AUTHENTIK_ISSUER %q is not a valid URL", cfg.AuthentikIssuer)
		}
	}
	if cfg.AuthentikJWKSURL != "" {
		if u, err := url.ParseRequestURI(cfg.AuthentikJWKSURL); err != nil || u.Host == "" {
			log.Fatalf("FATAL: AUTHENTIK_JWKS_URL %q is not a valid URL", cfg.AuthentikJWKSURL)
		}
	}
	if cfg.PublicBaseURL != "" {
		if u, err := url.ParseRequestURI(cfg.PublicBaseURL); err != nil || u.Scheme == "" || u.Host == "" {
			log.Fatalf("FATAL: PUBLIC_BASE_URL %q is not a valid URL", cfg.PublicBaseURL)
		}
	}
	if cfg.ControlOAuthRedirectURI != "" {
		if u, err := url.ParseRequestURI(cfg.ControlOAuthRedirectURI); err != nil || u.Scheme != "https" || u.Host == "" {
			log.Fatalf("FATAL: CONTROL_OAUTH_REDIRECT_URI %q must be an absolute HTTPS URL", cfg.ControlOAuthRedirectURI)
		}
	}

	// Reject insecure production settings.
	if cfg.AppEnv == "production" {
		if cfg.CoreTLSSkipVerify {
			log.Fatal("FATAL: CORE_TLS_SKIP_VERIFY must not be enabled in production")
		}
		if cfg.CoreAllowedHosts == "" {
			log.Fatal("FATAL: CORE_ALLOWED_HOSTS must be set in production; an empty value trusts all core server hosts and allows any host to register as a VPN server")
		}
		if cfg.TrustedProxies == "" {
			log.Fatal("FATAL: TRUSTED_PROXIES must be set in production; an empty value accepts X-Forwarded-For from any client, making IP-based rate limiting bypassable")
		}
	}

	if origin, ok := OriginFromURL(cfg.PublicBaseURL); ok && !OriginAllowed(origin, cfg.CORSAllowedOrigins) {
		slog.Warn("PUBLIC_BASE_URL origin is not present in CORS_ALLOWED_ORIGINS; OAuth refresh/logout CSRF checks may reject first-party clients",
			"public_base_origin", origin,
			"cors_allowed_origins", cfg.CORSAllowedOrigins,
		)
	}

	cfg.ExtensionCallbackPath = strings.TrimSpace(cfg.ExtensionCallbackPath)
	if !strings.HasPrefix(cfg.ExtensionCallbackPath, "/") {
		log.Fatalf("FATAL: EXTENSION_CALLBACK_PATH %q must start with /", cfg.ExtensionCallbackPath)
	}

	if env("DATABASE_URL") == "" && cfg.AuthentikClientID != "" {
		slog.Info("DATABASE_URL not set — deriving PostgreSQL connection string from POSTGRES_* variables")
	}

	// Validate numeric ranges
	if cfg.WGPort < 1 || cfg.WGPort > 65535 {
		log.Fatalf("FATAL: WG_PORT must be between 1 and 65535, got %d", cfg.WGPort)
	}
	if cfg.RateLimitRPS < 0 {
		log.Fatalf("FATAL: RATE_LIMIT_RPS must be >= 0, got %d", cfg.RateLimitRPS)
	}
	if cfg.RateLimitBurst < 1 && cfg.RateLimitRPS > 0 {
		log.Fatalf("FATAL: RATE_LIMIT_BURST must be >= 1 when rate limiting is enabled, got %d", cfg.RateLimitBurst)
	}
	if cfg.MaxDevicesPerUser < 0 {
		log.Fatalf("FATAL: MAX_DEVICES_PER_USER must be >= 0, got %d", cfg.MaxDevicesPerUser)
	}
	if cfg.ConnectRateLimitRPS < 0 {
		log.Fatalf("FATAL: CONNECT_RATE_LIMIT_RPS must be >= 0, got %g", cfg.ConnectRateLimitRPS)
	}
	if cfg.ConnectRateLimitBurst < 1 && cfg.ConnectRateLimitRPS > 0 {
		log.Fatalf("FATAL: CONNECT_RATE_LIMIT_BURST must be >= 1 when connect rate limiting is enabled, got %d", cfg.ConnectRateLimitBurst)
	}
	if cfg.ProxyPort < 1 || cfg.ProxyPort > 65535 {
		log.Fatalf("FATAL: PROXY_PORT must be between 1 and 65535, got %d", cfg.ProxyPort)
	}
	if cfg.ProxyMaxConnsPerUser < 1 {
		log.Fatalf("FATAL: PROXY_MAX_CONNS_PER_USER must be >= 1, got %d", cfg.ProxyMaxConnsPerUser)
	}
	if cfg.ProxyEnabled && !cfg.ProxyTLSEnabled && !cfg.ProxyTLSTerminated {
		log.Fatal("FATAL: proxy requires PROXY_TLS_ENABLED=true or PROXY_TLS_TERMINATED_BY_NGINX=true")
	}
	if cfg.ProxyTLSEnabled && cfg.ProxyTLSTerminated {
		log.Fatal("FATAL: configure either direct proxy TLS or Nginx TLS termination, not both")
	}
	if cfg.ProxyEnabled && cfg.ProxyTLSEnabled && (cfg.ProxyTLSCert == "" || cfg.ProxyTLSKey == "") {
		log.Fatal("FATAL: PROXY_TLS_CERT and PROXY_TLS_KEY are required when direct proxy TLS is enabled")
	}
	if cfg.WSSTunnelMaxClients < 1 {
		log.Fatal("FATAL: WSS_TUNNEL_MAX_CLIENTS must be >= 1")
	}
	if cfg.WSSTunnelEnabled {
		if _, err := uuid.Parse(cfg.WSSTunnelServerID); err != nil {
			log.Fatal("FATAL: WSS_TUNNEL_SERVER_ID must be the UUID of this Core server when WSS_TUNNEL_ENABLED=true")
		}
	}
	if cfg.MasquePort < 1 || cfg.MasquePort > 65535 {
		log.Fatalf("FATAL: MASQUE_PORT must be between 1 and 65535, got %d", cfg.MasquePort)
	}
	if cfg.MasqueMaxClients < 1 {
		log.Fatal("FATAL: MASQUE_MAX_CLIENTS must be >= 1")
	}
	if cfg.MasqueEnabled {
		if _, err := uuid.Parse(cfg.MasqueServerID); err != nil {
			log.Fatal("FATAL: MASQUE_SERVER_ID must be the UUID of this Core server when MASQUE_ENABLED=true")
		}
		if cfg.MasqueTLSCert == "" || cfg.MasqueTLSKey == "" || cfg.MasqueURITemplate == "" {
			log.Fatal("FATAL: MASQUE_TLS_CERT, MASQUE_TLS_KEY and MASQUE_URI_TEMPLATE are required when MASQUE_ENABLED=true")
		}
		template, err := uritemplate.New(cfg.MasqueURITemplate)
		if err != nil {
			log.Fatal("FATAL: MASQUE_URI_TEMPLATE must be a valid URI template")
		}
		expanded, err := template.Expand(uritemplate.Values{"target_host": uritemplate.String("127.0.0.1"), "target_port": uritemplate.String(strconv.Itoa(cfg.WGPort))})
		parsed, parseErr := url.Parse(expanded)
		if err != nil || parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" {
			log.Fatal("FATAL: MASQUE_URI_TEMPLATE must be an absolute HTTPS URI template")
		}
	}
	for name, limit := range map[string]int{
		"WS_MAX_GLOBAL": cfg.WSMaxGlobal,
		"WS_MAX_FREE":   cfg.WSMaxFree,
		"WS_MAX_BASIC":  cfg.WSMaxBasic,
		"WS_MAX_MEDIUM": cfg.WSMaxMedium,
		"WS_MAX_PRO":    cfg.WSMaxPro,
		"WS_MAX_ADMIN":  cfg.WSMaxAdmin,
	} {
		if limit < 0 {
			log.Fatalf("FATAL: %s must be >= 0, got %d", name, limit)
		}
	}

	// Validate VPN_DNS entries are parseable IP addresses.
	dnsCount := 0
	for _, entry := range strings.Split(cfg.VpnDNS, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if net.ParseIP(entry) == nil {
			log.Fatalf("FATAL: VPN_DNS contains invalid IP address %q", entry)
		}
		dnsCount++
	}
	if dnsCount == 0 {
		log.Fatal("FATAL: VPN_DNS must contain at least one IP address")
	}
	if (cfg.AstianPaymentURL == "") != (cfg.AstianPaymentToken == "") {
		log.Fatal("FATAL: ASTIAN_PAYMENT_URL and ASTIAN_PAYMENT_INTERNAL_TOKEN must be configured together")
	}

	return cfg
}

func (c *Config) AuthentikAppURL() string {
	return strings.TrimRight(c.AuthentikIssuer, "/")
}

func (c *Config) AuthentikOrigin() string {
	appURL := c.AuthentikAppURL()
	if appURL == "" {
		return ""
	}
	parsed, err := url.Parse(appURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return appURL
	}
	return parsed.Scheme + "://" + parsed.Host
}

func (c *Config) AuthentikTokenIssuer() string {
	origin := c.AuthentikOrigin()
	if origin == "" {
		return ""
	}
	return origin + "/"
}

func (c *Config) AuthentikAuthorizationURL() string {
	origin := c.AuthentikOrigin()
	if origin == "" {
		return ""
	}
	return origin + "/application/o/authorize/"
}

func (c *Config) AuthentikTokenURL() string {
	origin := c.AuthentikOrigin()
	if origin == "" {
		return ""
	}
	return origin + "/application/o/token/"
}

func (c *Config) AuthentikUserInfoURL() string {
	origin := c.AuthentikOrigin()
	if origin == "" {
		return ""
	}
	return origin + "/application/o/userinfo/"
}

func (c *Config) AuthentikIntrospectionURL() string {
	if c.AuthentikIntrospectionURLOverride != "" {
		return c.AuthentikIntrospectionURLOverride
	}
	appURL := c.AuthentikAppURL()
	if appURL != "" {
		return appURL + "/introspect/"
	}
	origin := c.AuthentikOrigin()
	if origin == "" {
		return ""
	}
	return origin + "/application/o/introspect/"
}

func (c *Config) AuthentikEndSessionURL() string {
	appURL := c.AuthentikAppURL()
	if appURL == "" {
		return ""
	}
	return appURL + "/end-session/"
}

func (c *Config) ExtensionCallbackURL() string {
	if c.PublicBaseURL == "" {
		return ""
	}
	return strings.TrimRight(c.PublicBaseURL, "/") + c.ExtensionCallbackPath
}

func OriginFromURL(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	return parsed.Scheme + "://" + parsed.Host, true
}

func OriginAllowed(origin, allowedCSV string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	for _, allowed := range strings.Split(allowedCSV, ",") {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		if allowed == origin {
			return true
		}
		if strings.HasPrefix(allowed, "https://*.") || strings.HasPrefix(allowed, "http://*.") {
			scheme := allowed[:strings.Index(allowed, "://")]
			suffix := allowed[strings.Index(allowed, "*.")+1:]
			if parsed.Scheme == scheme && strings.HasSuffix(parsed.Host, suffix) {
				return true
			}
		}
	}
	return false
}

// WSMaxForGroups returns the highest WS connection limit for the given groups.
func (c *Config) WSMaxForGroups(groups []string) int {
	max := c.WSMaxFree
	for _, g := range groups {
		var limit int
		switch g {
		case "vpn-admins", "admins", "authentik Admins":
			limit = c.WSMaxAdmin
		case "plan-pro":
			limit = c.WSMaxPro
		case "plan-medium":
			limit = c.WSMaxMedium
		case "plan-basic":
			limit = c.WSMaxBasic
		}
		if limit > max {
			max = limit
		}
	}
	return max
}

func databaseURLFromEnv() string {
	if v := env("DATABASE_URL"); v != "" {
		return v
	}
	if !anyEnvNonEmpty("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB", "POSTGRES_SSLMODE") {
		return ""
	}

	u := &url.URL{
		Scheme: "postgres",
		User:   databaseUserInfo(requireEnv("POSTGRES_USER"), requireEnv("POSTGRES_PASSWORD")),
		Host:   net.JoinHostPort(requireEnv("POSTGRES_HOST"), strconv.Itoa(requireEnvInt("POSTGRES_PORT"))),
		Path:   requireEnv("POSTGRES_DB"),
	}
	q := u.Query()
	q.Set("sslmode", requireEnv("POSTGRES_SSLMODE"))
	u.RawQuery = q.Encode()
	return u.String()
}

func databaseUserInfo(user, password string) *url.Userinfo {
	if password == "" {
		return url.User(user)
	}
	return url.UserPassword(user, password)
}

func redisURLFromEnv() string {
	if v := env("REDIS_URL"); v != "" {
		return v
	}
	if !anyEnvNonEmpty("REDIS_PASSWORD", "REDIS_HOST", "REDIS_PORT", "REDIS_DB") {
		return ""
	}

	u := &url.URL{
		Scheme: "redis",
		Host:   net.JoinHostPort(requireEnv("REDIS_HOST"), strconv.Itoa(requireEnvInt("REDIS_PORT"))),
		Path:   requireEnv("REDIS_DB"),
	}
	u.User = url.UserPassword("", requireEnv("REDIS_PASSWORD"))
	return u.String()
}

func env(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func anyEnvNonEmpty(keys ...string) bool {
	for _, key := range keys {
		if env(key) != "" {
			return true
		}
	}
	return false
}

func requireEnv(key string) string {
	v := env(key)
	if v == "" {
		log.Fatalf("FATAL: %s is required", key)
	}
	return v
}

func requireEnvInt(key string) int {
	v := requireEnv(key)
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("FATAL: %s must be an integer, got %q", key, v)
	}
	return n
}

func envIntDefault(key string, defaultValue int) int {
	v := env(key)
	if v == "" {
		return defaultValue
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("FATAL: %s must be an integer, got %q", key, v)
	}
	return n
}

func requireEnvFloat(key string) float64 {
	v := requireEnv(key)
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		log.Fatalf("FATAL: %s must be a number, got %q", key, v)
	}
	return f
}

func requireEnvBool(key string) bool {
	v := requireEnv(key)
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES", "on", "ON":
		return true
	case "0", "false", "FALSE", "False", "no", "NO", "off", "OFF":
		return false
	default:
		log.Fatalf("FATAL: %s must be a boolean, got %q", key, v)
		return false
	}
}

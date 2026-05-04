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
)

type Config struct {
	// Application
	AppEnv string // "production" or "development"

	// HTTP
	Port      string
	AuthToken string // X-Core-Token shared secret (core ↔ core API)

	// CORS
	CORSAllowedOrigins string // comma-separated list of allowed origins

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

	// HTTP CONNECT proxy
	ProxyEnabled        bool // enable the HTTP CONNECT forward proxy
	ProxyPort           int  // TCP port for the forward proxy (default 8888)
	ProxyMaxConnsPerUser int  // max concurrent CONNECT tunnels per user (default 20)

	// WebSocket limits per plan
	WSMaxGlobal int // max global WS connections (0 = unlimited)
	WSMaxFree   int // max WS conns for free plan
	WSMaxBasic  int // max WS conns for basic plan
	WSMaxMedium int // max WS conns for medium plan
	WSMaxPro    int // max WS conns for pro plan
	WSMaxAdmin  int // max WS conns for admins
}

// wgInterfaceRe allows only safe characters for a WireGuard interface name.
// Linux netdev names are limited to 15 characters, alphanumeric plus - and _.
var wgInterfaceRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

func Load() *Config {
	issuer := strings.TrimRight(getEnv("AUTHENTIK_ISSUER", ""), "/")

	jwksURL := getEnv("AUTHENTIK_JWKS_URL", "")
	if jwksURL == "" && issuer != "" {
		jwksURL = strings.TrimRight(issuer, "/") + "/jwks/"
	}

	cfg := &Config{
		AppEnv:      getEnv("APP_ENV", "production"),
		Port:        getEnv("VPN_CORE_PORT", "8080"),
		AuthToken:   getEnv("VPN_CORE_TOKEN", ""),
		WGInterface: getEnv("WG_INTERFACE", "wg0"),
		WGPort:      getEnvInt("WG_PORT", 51820),
		Subnet:      getEnv("WG_SUBNET", "10.8.0.0/16"),
		ConfigDir:   getEnv("WG_CONFIG_DIR", "/etc/wireguard"),
		Endpoint:    getEnv("WG_ENDPOINT", ""),

		CORSAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", ""),

		DatabaseURL:                       getEnv("DATABASE_URL", ""),
		RedisURL:                          getEnv("REDIS_URL", ""),
		AuthentikIssuer:                   issuer,
		AuthentikClientID:                 getEnv("AUTHENTIK_CLIENT_ID", ""),
		AuthentikClientSecret:             getEnv("AUTHENTIK_CLIENT_SECRET", ""),
		AuthentikJWKSURL:                  jwksURL,
		AuthentikIntrospectionURLOverride: getEnv("AUTHENTIK_INTROSPECTION_URL", ""),

		CoreTLSSkipVerify: getEnvBool("CORE_TLS_SKIP_VERIFY", false),
		CoreAllowHTTP:     getEnvBool("CORE_ALLOW_INSECURE_HTTP", false),
		CoreAllowedHosts:  getEnv("CORE_ALLOWED_HOSTS", ""),

		RateLimitRPS:   getEnvInt("RATE_LIMIT_RPS", 20),
		RateLimitBurst: getEnvInt("RATE_LIMIT_BURST", 40),

		TrustedProxies: getEnv("TRUSTED_PROXIES", ""),

		MaxDevicesPerUser: getEnvInt("MAX_DEVICES_PER_USER", 5),

		ConnectRateLimitRPS:   getEnvFloat("CONNECT_RATE_LIMIT_RPS", 0.5),
		ConnectRateLimitBurst: getEnvInt("CONNECT_RATE_LIMIT_BURST", 3),

		VpnDNS: getEnv("VPN_DNS", "1.1.1.1, 8.8.8.8"),

		ProxyEnabled:        getEnvBool("PROXY_ENABLED", false),
		ProxyPort:           getEnvInt("PROXY_PORT", 8888),
		ProxyMaxConnsPerUser: getEnvInt("PROXY_MAX_CONNS_PER_USER", 20),

		WSMaxGlobal: getEnvInt("WS_MAX_GLOBAL", 1000),
		WSMaxFree:   getEnvInt("WS_MAX_FREE", 1),
		WSMaxBasic:  getEnvInt("WS_MAX_BASIC", 2),
		WSMaxMedium: getEnvInt("WS_MAX_MEDIUM", 3),
		WSMaxPro:    getEnvInt("WS_MAX_PRO", 5),
		WSMaxAdmin:  getEnvInt("WS_MAX_ADMIN", 10),
	}

	if cfg.AuthToken == "" {
		log.Fatal("FATAL: VPN_CORE_TOKEN is not set — the core API cannot authenticate any request; set VPN_CORE_TOKEN to a strong random secret")
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

	// Apply environment-aware CORS default when not explicitly configured
	if cfg.CORSAllowedOrigins == "" {
		if cfg.AppEnv == "development" {
			cfg.CORSAllowedOrigins = "https://*.astian.org,http://localhost:5173,http://localhost:3000"
		} else {
			cfg.CORSAllowedOrigins = "https://*.astian.org"
		}
	}

	if cfg.DatabaseURL == "" {
		slog.Info("DATABASE_URL not set — Control API will be disabled")
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
	if cfg.ProxyPort < 1 || cfg.ProxyPort > 65535 {
		log.Fatalf("FATAL: PROXY_PORT must be between 1 and 65535, got %d", cfg.ProxyPort)
	}
	if cfg.ProxyMaxConnsPerUser < 1 {
		log.Fatalf("FATAL: PROXY_MAX_CONNS_PER_USER must be >= 1, got %d", cfg.ProxyMaxConnsPerUser)
	}

	// Validate VPN_DNS entries are parseable IP addresses.
	for _, entry := range strings.Split(cfg.VpnDNS, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if net.ParseIP(entry) == nil {
			log.Fatalf("FATAL: VPN_DNS contains invalid IP address %q", entry)
		}
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

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		slog.Warn("invalid integer env var, using default", "key", key, "value", v, "default", fallback)
		return fallback
	}
	return n
}

func getEnvFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		slog.Warn("invalid float env var, using default", "key", key, "value", v, "default", fallback)
		return fallback
	}
	return f
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES", "on", "ON":
		return true
	case "0", "false", "FALSE", "False", "no", "NO", "off", "OFF":
		return false
	default:
		return fallback
	}
}

package config

import (
	"log"
	"os"
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
	AuthentikIssuer   string
	AuthentikClientID string
	AuthentikJWKSURL  string

	// Core-to-core TLS
	CoreTLSSkipVerify bool // skip TLS cert verification for self-signed certs
	CoreAllowHTTP     bool // allow plain HTTP for local/testing inter-core calls

	// Rate limiting
	RateLimitRPS   int // requests per second per IP (0 = disabled)
	RateLimitBurst int // burst size for rate limiter

	// Device limits
	MaxDevicesPerUser int // max active connections per user (0 = unlimited)
}

func Load() *Config {
	issuer := getEnv("AUTHENTIK_ISSUER", "")

	jwksURL := getEnv("AUTHENTIK_JWKS_URL", "")
	if jwksURL == "" && issuer != "" {
		jwksURL = issuer + "/jwks/"
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

		CORSAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", "https://*.astian.org,http://localhost:5173,http://localhost:3000"),

		DatabaseURL:       getEnv("DATABASE_URL", ""),
		RedisURL:          getEnv("REDIS_URL", ""),
		AuthentikIssuer:   issuer,
		AuthentikClientID: getEnv("AUTHENTIK_CLIENT_ID", ""),
		AuthentikJWKSURL:  jwksURL,

		CoreTLSSkipVerify: getEnvBool("CORE_TLS_SKIP_VERIFY", false),
		CoreAllowHTTP:     getEnvBool("CORE_ALLOW_INSECURE_HTTP", false),

		RateLimitRPS:   getEnvInt("RATE_LIMIT_RPS", 20),
		RateLimitBurst: getEnvInt("RATE_LIMIT_BURST", 40),

		MaxDevicesPerUser: getEnvInt("MAX_DEVICES_PER_USER", 5),
	}

	if cfg.AuthToken == "" {
		log.Println("WARNING: VPN_CORE_TOKEN is empty — all requests will be rejected")
	}

	if cfg.DatabaseURL == "" {
		log.Println("INFO: DATABASE_URL not set — Control API will be disabled")
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

	return cfg
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
	var n int
	for _, c := range v {
		if c < '0' || c > '9' {
			return fallback
		}
		n = n*10 + int(c-'0')
	}
	return n
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

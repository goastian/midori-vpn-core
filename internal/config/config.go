package config

import (
	"log"
	"os"
)

type Config struct {
	// HTTP
	Port      string
	AuthToken string // X-Core-Token shared secret (core ↔ core API)

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
}

func Load() *Config {
	issuer := getEnv("AUTHENTIK_ISSUER", "")

	jwksURL := getEnv("AUTHENTIK_JWKS_URL", "")
	if jwksURL == "" && issuer != "" {
		jwksURL = issuer + "/jwks/"
	}

	cfg := &Config{
		Port:        getEnv("VPN_CORE_PORT", "8080"),
		AuthToken:   getEnv("VPN_CORE_TOKEN", ""),
		WGInterface: getEnv("WG_INTERFACE", "wg0"),
		WGPort:      getEnvInt("WG_PORT", 51820),
		Subnet:      getEnv("WG_SUBNET", "10.8.0.0/16"),
		ConfigDir:   getEnv("WG_CONFIG_DIR", "/etc/wireguard"),
		Endpoint:    getEnv("WG_ENDPOINT", ""),

		DatabaseURL:       getEnv("DATABASE_URL", ""),
		RedisURL:          getEnv("REDIS_URL", ""),
		AuthentikIssuer:   issuer,
		AuthentikClientID: getEnv("AUTHENTIK_CLIENT_ID", ""),
		AuthentikJWKSURL:  jwksURL,
	}

	if cfg.AuthToken == "" {
		log.Println("WARNING: VPN_CORE_TOKEN is empty — all requests will be rejected")
	}

	if cfg.DatabaseURL == "" {
		log.Println("INFO: DATABASE_URL not set — Control API will be disabled")
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

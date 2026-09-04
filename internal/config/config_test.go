package config

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestAuthentikURLsFromApplicationURL(t *testing.T) {
	cfg := &Config{
		AuthentikIssuer:  "https://accounts.astian.org/application/o/midori-vpn",
		AuthentikJWKSURL: "https://accounts.astian.org/application/o/midori-vpn/jwks/",
	}

	if got := cfg.AuthentikTokenIssuer(); got != "https://accounts.astian.org/" {
		t.Fatalf("AuthentikTokenIssuer() = %q", got)
	}
	if got := cfg.AuthentikAuthorizationURL(); got != "https://accounts.astian.org/application/o/authorize/" {
		t.Fatalf("AuthentikAuthorizationURL() = %q", got)
	}
	if got := cfg.AuthentikTokenURL(); got != "https://accounts.astian.org/application/o/token/" {
		t.Fatalf("AuthentikTokenURL() = %q", got)
	}
	if got := cfg.AuthentikUserInfoURL(); got != "https://accounts.astian.org/application/o/userinfo/" {
		t.Fatalf("AuthentikUserInfoURL() = %q", got)
	}
	if got := cfg.AuthentikIntrospectionURL(); got != "https://accounts.astian.org/application/o/midori-vpn/introspect/" {
		t.Fatalf("AuthentikIntrospectionURL() = %q", got)
	}
	if got := cfg.AuthentikEndSessionURL(); got != "https://accounts.astian.org/application/o/midori-vpn/end-session/" {
		t.Fatalf("AuthentikEndSessionURL() = %q", got)
	}
	if got := cfg.AuthentikJWKSURL; got != "https://accounts.astian.org/application/o/midori-vpn/jwks/" {
		t.Fatalf("AuthentikJWKSURL = %q", got)
	}
	if got := cfg.AuthentikOrigin(); got != "https://accounts.astian.org" {
		t.Fatalf("AuthentikOrigin() = %q", got)
	}
}

func TestAuthentikIntrospectionURLOverride(t *testing.T) {
	cfg := &Config{
		AuthentikIssuer:                   "https://accounts.astian.org/application/o/midori-vpn",
		AuthentikIntrospectionURLOverride: "https://accounts.astian.org/application/o/introspect/",
	}

	if got := cfg.AuthentikIntrospectionURL(); got != "https://accounts.astian.org/application/o/introspect/" {
		t.Fatalf("AuthentikIntrospectionURL() override = %q", got)
	}
}

func TestDatabaseURLFromEnvPrefersExplicitURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://custom:secret@db.example.com:5433/customdb?sslmode=require")
	t.Setenv("POSTGRES_USER", "ignored")
	t.Setenv("POSTGRES_PASSWORD", "ignored")
	t.Setenv("POSTGRES_HOST", "ignored")
	t.Setenv("POSTGRES_PORT", "15432")
	t.Setenv("POSTGRES_DB", "ignored")
	t.Setenv("POSTGRES_SSLMODE", "disable")

	got := databaseURLFromEnv()
	want := "postgres://custom:secret@db.example.com:5433/customdb?sslmode=require"
	if got != want {
		t.Fatalf("databaseURLFromEnv() = %q, want %q", got, want)
	}
}

func TestDatabaseURLFromPostgresEnv(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("POSTGRES_RUNTIME_USER", "")
	t.Setenv("POSTGRES_RUNTIME_PASSWORD", "")
	t.Setenv("POSTGRES_USER", "vpn_user")
	t.Setenv("POSTGRES_PASSWORD", "vpn_secret")
	t.Setenv("POSTGRES_HOST", "postgres.internal")
	t.Setenv("POSTGRES_PORT", "15432")
	t.Setenv("POSTGRES_DB", "vpn_db")
	t.Setenv("POSTGRES_SSLMODE", "require")

	got := databaseURLFromEnv()
	want := "postgres://vpn_user:vpn_secret@postgres.internal:15432/vpn_db?sslmode=require"
	if got != want {
		t.Fatalf("databaseURLFromEnv() = %q, want %q", got, want)
	}
}

func TestDatabaseURLFromDedicatedRuntimeRole(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("POSTGRES_RUNTIME_USER", "vpn_runtime")
	t.Setenv("POSTGRES_RUNTIME_PASSWORD", "runtime_secret")
	t.Setenv("POSTGRES_HOST", "pgbouncer.internal")
	t.Setenv("POSTGRES_PORT", "6432")
	t.Setenv("POSTGRES_DB", "vpn_db")
	t.Setenv("POSTGRES_SSLMODE", "require")

	got := databaseURLFromEnv()
	want := "postgres://vpn_runtime:runtime_secret@pgbouncer.internal:6432/vpn_db?sslmode=require"
	if got != want {
		t.Fatalf("databaseURLFromEnv() = %q, want %q", got, want)
	}
}

func TestMigrationDatabaseURLFromDedicatedRole(t *testing.T) {
	t.Setenv("MIGRATION_DATABASE_URL", "")
	t.Setenv("POSTGRES_MIGRATOR_USER", "vpn_migrator")
	t.Setenv("POSTGRES_MIGRATOR_PASSWORD", "migration_secret")
	t.Setenv("POSTGRES_MIGRATION_HOST", "postgres.internal")
	t.Setenv("POSTGRES_MIGRATION_PORT", "5432")
	t.Setenv("POSTGRES_DB", "vpn_db")
	t.Setenv("POSTGRES_MIGRATION_SSLMODE", "verify-full")

	got := MigrationDatabaseURLFromEnv()
	want := "postgres://vpn_migrator:migration_secret@postgres.internal:5432/vpn_db?sslmode=verify-full"
	if got != want {
		t.Fatalf("migrationDatabaseURLFromEnv() = %q, want %q", got, want)
	}
}

func TestRedisURLFromEnvPrefersExplicitURL(t *testing.T) {
	t.Setenv("REDIS_URL", "redis://:custom-secret@cache.example.com:6380/2")
	t.Setenv("REDIS_PASSWORD", "ignored")
	t.Setenv("REDIS_HOST", "ignored")
	t.Setenv("REDIS_PORT", "6379")
	t.Setenv("REDIS_DB", "0")

	got := redisURLFromEnv()
	want := "redis://:custom-secret@cache.example.com:6380/2"
	if got != want {
		t.Fatalf("redisURLFromEnv() = %q, want %q", got, want)
	}
}

func TestRedisURLFromRedisEnv(t *testing.T) {
	t.Setenv("REDIS_URL", "")
	t.Setenv("REDIS_PASSWORD", "redis_secret")
	t.Setenv("REDIS_HOST", "redis.internal")
	t.Setenv("REDIS_PORT", "6380")
	t.Setenv("REDIS_DB", "2")

	got := redisURLFromEnv()
	want := "redis://:redis_secret@redis.internal:6380/2"
	if got != want {
		t.Fatalf("redisURLFromEnv() = %q, want %q", got, want)
	}
}

func TestDatabaseURLFromEnvRemainsDisabledWithoutDatabaseSettings(t *testing.T) {
	for _, key := range []string{"DATABASE_URL", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB", "POSTGRES_SSLMODE"} {
		t.Setenv(key, "")
	}
	if got := databaseURLFromEnv(); got != "" {
		t.Fatalf("databaseURLFromEnv() = %q, want disabled", got)
	}
}

func TestRedisURLFromEnvRemainsDisabledWithoutRedisSettings(t *testing.T) {
	for _, key := range []string{"REDIS_URL", "REDIS_PASSWORD", "REDIS_HOST", "REDIS_PORT", "REDIS_DB"} {
		t.Setenv(key, "")
	}
	if got := redisURLFromEnv(); got != "" {
		t.Fatalf("redisURLFromEnv() = %q, want disabled", got)
	}
}

func TestCoreNodeNameRequiresCompleteDNSLabel(t *testing.T) {
	valid := []string{"a", "node-1", strings.Repeat("a", 63)}
	for _, name := range valid {
		if !coreNodeNameRe.MatchString(name) {
			t.Errorf("valid Core node name %q was rejected", name)
		}
	}
	invalid := []string{"", "node-", "-node", "Node", strings.Repeat("a", 64)}
	for _, name := range invalid {
		if coreNodeNameRe.MatchString(name) {
			t.Errorf("invalid Core node name %q was accepted", name)
		}
	}
}

func TestRequireEnvFailsFastWhenMissing(t *testing.T) {
	if os.Getenv("MIDORIVPN_REQUIRE_ENV_HELPER") == "1" {
		_ = requireEnv("MIDORIVPN_REQUIRED_SETTING")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRequireEnvFailsFastWhenMissing")
	cmd.Env = append(os.Environ(), "MIDORIVPN_REQUIRE_ENV_HELPER=1", "MIDORIVPN_REQUIRED_SETTING=")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("missing required environment variable did not terminate startup")
	}
	if !strings.Contains(string(output), "MIDORIVPN_REQUIRED_SETTING is required") {
		t.Fatalf("missing-variable error is not explicit: %s", output)
	}
}

func TestLoadAcceptsPublicPKCEClientWithoutSecret(t *testing.T) {
	if os.Getenv("MIDORIVPN_PUBLIC_PKCE_HELPER") == "1" {
		cfg := Load()
		if cfg.AllowLegacyHMACTransportTokens || cfg.CredentialSigningSecret != "" {
			t.Fatal("default asymmetric configuration unexpectedly enabled legacy HMAC credentials")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestLoadAcceptsPublicPKCEClientWithoutSecret")
	cmd.Env = append(os.Environ(),
		"MIDORIVPN_PUBLIC_PKCE_HELPER=1",
		"APP_ENV=development",
		"VPN_CORE_PORT=8085",
		"NODE_AUTHORIZED_KEYS=control=test-public-key",
		"CONTROL_NODE_ID=control",
		"CONTROL_NODE_PRIVATE_KEY=test-private-key",
		"TRANSPORT_TOKEN_ISSUER=https://vpn.example.test",
		"TRANSPORT_TOKEN_AUTHORIZED_KEYS=control=test-public-key",
		"ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS=false",
		"WG_INTERFACE=wgtest0",
		"WG_PORT=51820",
		"WG_SUBNET=10.8.0.0/16",
		"WG_CONFIG_DIR=/tmp/midorivpn-test",
		"WG_ENDPOINT=vpn.example.test",
		"CORS_ALLOWED_ORIGINS=https://vpn.example.test",
		"PUBLIC_BASE_URL=https://vpn.example.test",
		"EXTENSION_CALLBACK_PATH=/extension/callback",
		"DATABASE_URL=postgres://user:password@db.example.test:5432/midori?sslmode=require",
		"CONTROL_DATA_ENCRYPTION_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		"REDIS_URL=redis://:password@redis.example.test:6379/0",
		"AUTHENTIK_ISSUER=https://accounts.example.test/application/o/midori-vpn",
		"AUTHENTIK_CLIENT_ID=public-client",
		"AUTHENTIK_CLIENT_SECRET=",
		"OAUTH_ALLOWED_REDIRECT_URIS=http://127.0.0.1:7071/oauth/callback",
		"CONTROL_OAUTH_REDIRECT_URI=https://vpn.example.test/auth/callback",
		"CORE_TLS_SKIP_VERIFY=false",
		"CORE_ALLOW_INSECURE_HTTP=false",
		"RATE_LIMIT_RPS=20",
		"RATE_LIMIT_BURST=40",
		"MAX_DEVICES_PER_USER=5",
		"CONNECT_RATE_LIMIT_RPS=0.5",
		"CONNECT_RATE_LIMIT_BURST=3",
		"VPN_DNS=10.8.0.53",
		"PROXY_ENABLED=false",
		"PROXY_PORT=8443",
		"PROXY_MAX_CONNS_PER_USER=20",
		"PROXY_TLS_ENABLED=false",
		"PROXY_TLS_TERMINATED_BY_NGINX=false",
		"PROXY_SERVER_ID=",
		"WSS_TUNNEL_ENABLED=false",
		"WSS_TUNNEL_MAX_CLIENTS=100",
		"MASQUE_ENABLED=false",
		"MASQUE_PORT=443",
		"MASQUE_MAX_CLIENTS=100",
		"WS_MAX_GLOBAL=1000",
		"WS_MAX_FREE=1",
		"WS_MAX_BASIC=2",
		"WS_MAX_MEDIUM=3",
		"WS_MAX_PRO=5",
		"WS_MAX_ADMIN=10",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("public PKCE configuration was rejected: %v\n%s", err, output)
	}
}

func TestOriginFromURL(t *testing.T) {
	got, ok := OriginFromURL("https://vpn.astian.org/extension/callback")
	if !ok {
		t.Fatal("OriginFromURL() ok = false, want true")
	}
	if got != "https://vpn.astian.org" {
		t.Fatalf("OriginFromURL() = %q, want %q", got, "https://vpn.astian.org")
	}

	if _, ok := OriginFromURL("vpn.astian.org"); ok {
		t.Fatal("OriginFromURL() ok = true for URL without scheme")
	}
}

func TestOriginAllowed(t *testing.T) {
	tests := []struct {
		name    string
		origin  string
		allowed string
		want    bool
	}{
		{name: "exact", origin: "https://vpn.astian.org", allowed: "https://vpn.astian.org", want: true},
		{name: "second explicit origin", origin: "https://desktop.astian.org", allowed: "https://vpn.astian.org,https://desktop.astian.org", want: true},
		{name: "wildcard", origin: "https://vpn.astian.org", allowed: "https://*.astian.org", want: true},
		{name: "wrong scheme", origin: "http://vpn.astian.org", allowed: "https://*.astian.org", want: false},
		{name: "rejected", origin: "https://evil.example", allowed: "https://vpn.astian.org,https://desktop.astian.org", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OriginAllowed(tt.origin, tt.allowed); got != tt.want {
				t.Fatalf("OriginAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

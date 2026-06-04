package config

import "testing"

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

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
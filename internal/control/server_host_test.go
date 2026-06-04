package control

import "testing"

func TestNormalizeAdminServerHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     int
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{
			name:     "plain host",
			host:     "vpn.example.org",
			port:     8085,
			wantHost: "vpn.example.org",
			wantPort: 8085,
		},
		{
			name:     "http url without explicit port",
			host:     "http://vpn.example.org",
			port:     8085,
			wantHost: "vpn.example.org",
			wantPort: 8085,
		},
		{
			name:     "https url with explicit port",
			host:     "https://vpn.example.org:9443",
			port:     8085,
			wantHost: "vpn.example.org",
			wantPort: 9443,
		},
		{
			name:    "url with path is invalid",
			host:    "https://vpn.example.org/api",
			port:    8085,
			wantErr: true,
		},
		{
			name:    "invalid port",
			host:    "vpn.example.org",
			port:    0,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotHost, gotPort, err := normalizeAdminServerHost(tc.host, tc.port)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotHost != tc.wantHost {
				t.Fatalf("host mismatch: got %q want %q", gotHost, tc.wantHost)
			}
			if gotPort != tc.wantPort {
				t.Fatalf("port mismatch: got %d want %d", gotPort, tc.wantPort)
			}
		})
	}
}

func TestDefaultAdminServerPort(t *testing.T) {
	if got := defaultAdminServerPort(false); got != 443 {
		t.Fatalf("secure default port mismatch: got %d want 443", got)
	}
	if got := defaultAdminServerPort(true); got != 8080 {
		t.Fatalf("insecure default port mismatch: got %d want 8080", got)
	}
}

func TestWireGuardEndpointForServerHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "plain host", host: "vpn.example.org", port: 51820, want: "vpn.example.org:51820"},
		{name: "url host", host: "http://vpn.example.org", port: 51820, want: "vpn.example.org:51820"},
		{name: "host with api port", host: "http://vpn.example.org:8085", port: 51820, want: "vpn.example.org:51820"},
		{name: "ipv6", host: "::1", port: 51820, want: "[::1]:51820"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := wireGuardEndpointForServerHost(tc.host, tc.port)
			if got != tc.want {
				t.Fatalf("endpoint mismatch: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestIsLoopbackServerHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{host: "localhost", want: true},
		{host: "http://localhost", want: true},
		{host: "127.0.0.1", want: true},
		{host: "::1", want: true},
		{host: "vpn.example.org", want: false},
	}

	for _, tc := range tests {
		got := isLoopbackServerHost(tc.host)
		if got != tc.want {
			t.Fatalf("host=%q got=%v want=%v", tc.host, got, tc.want)
		}
	}
}

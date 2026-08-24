package repo

import "testing"

func TestNormalizeStoredTransportHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "hostname with duplicate port", host: "vpn.example.test:51820", port: 51820, want: "vpn.example.test"},
		{name: "IPv4 with duplicate port", host: "192.0.2.10:443", port: 443, want: "192.0.2.10"},
		{name: "IPv6 with duplicate port", host: "[2001:db8::10]:443", port: 443, want: "2001:db8::10"},
		{name: "different port remains intact", host: "vpn.example.test:8443", port: 443, want: "vpn.example.test:8443"},
		{name: "bare hostname", host: "vpn.example.test", port: 443, want: "vpn.example.test"},
		{name: "bare IPv6", host: "2001:db8::10", port: 443, want: "2001:db8::10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeStoredTransportHost(test.host, test.port); got != test.want {
				t.Fatalf("normalizeStoredTransportHost(%q, %d) = %q, want %q", test.host, test.port, got, test.want)
			}
		})
	}
}

// Package clientip resolves request origin addresses across trusted reverse
// proxies without allowing callers to spoof forwarding headers.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

type TrustedProxies []*net.IPNet

// ParseTrustedProxies parses a comma-separated list of individual IPs and
// CIDRs. Invalid entries are ignored; production configuration validation is
// responsible for rejecting an unusable empty list.
func ParseTrustedProxies(raw string) TrustedProxies {
	var networks TrustedProxies
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			ip := net.ParseIP(value)
			if ip == nil {
				continue
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if _, network, err := net.ParseCIDR(value); err == nil {
			networks = append(networks, network)
		}
	}
	return networks
}

func (trusted TrustedProxies) contains(rawIP string) bool {
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return false
	}
	for _, network := range trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// RealIP accepts forwarding headers only from configured trusted proxies. It
// walks X-Forwarded-For from the trusted edge toward the original client so a
// caller cannot select its address by injecting the first header value.
func RealIP(r *http.Request, trusted TrustedProxies) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = strings.TrimSpace(r.RemoteAddr)
	}
	if !trusted.contains(remoteIP) {
		return remoteIP
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			if net.ParseIP(candidate) != nil && !trusted.contains(candidate) {
				return candidate
			}
		}
	}
	if candidate := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(candidate) != nil {
		return candidate
	}
	return remoteIP
}

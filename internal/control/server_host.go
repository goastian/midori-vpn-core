package control

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// normalizeAdminServerHost parses host input from admin APIs.
// It accepts plain hostnames/IPs and http(s) URLs, returning a canonical host plus port.
func normalizeAdminServerHost(rawHost string, port int) (string, int, error) {
	host := strings.TrimSpace(rawHost)
	if host == "" {
		return "", 0, fmt.Errorf("host is required")
	}

	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return "", 0, fmt.Errorf("invalid host URL")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", 0, fmt.Errorf("host URL must use http or https")
		}
		if u.Host == "" {
			return "", 0, fmt.Errorf("invalid host URL: missing host")
		}
		if u.Path != "" && u.Path != "/" {
			return "", 0, fmt.Errorf("host URL must not include a path")
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return "", 0, fmt.Errorf("host URL must not include query or fragment")
		}

		host = strings.TrimSpace(u.Hostname())
		if p := u.Port(); p != "" {
			parsed, err := strconv.Atoi(p)
			if err != nil {
				return "", 0, fmt.Errorf("invalid host URL port")
			}
			port = parsed
		}
	}

	host = strings.Trim(host, "[]")
	if host == "" {
		return "", 0, fmt.Errorf("host is required")
	}
	if strings.ContainsAny(host, "/?#") {
		return "", 0, fmt.Errorf("invalid host")
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port must be between 1 and 65535")
	}

	return host, port, nil
}

func defaultAdminServerPort(allowInsecureHTTP bool) int {
	if allowInsecureHTTP {
		return 8080
	}
	return 443
}

func endpointHostFromServerHost(rawHost string) string {
	host := strings.TrimSpace(rawHost)
	if host == "" {
		return ""
	}

	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil && u.Hostname() != "" {
			return strings.TrimSpace(u.Hostname())
		}
	}

	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(strings.TrimSpace(h), "[]")
	}

	return strings.Trim(strings.TrimSpace(host), "[]")
}

func wireGuardEndpointForServerHost(rawHost string, wgPort int) string {
	host := endpointHostFromServerHost(rawHost)
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(wgPort))
}

func isLoopbackServerHost(rawHost string) bool {
	host := endpointHostFromServerHost(rawHost)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

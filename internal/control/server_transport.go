package control

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/goastian/midori-vpn-core/internal/models"
)

var supportedTransportProtocols = map[string]struct{}{
	"wireguard": {}, "wss": {}, "masque": {}, "openvpn": {}, "ikev2": {}, "proxy": {},
}

// TransportRequest deliberately omits health fields: operators configure a
// gateway, while the health checker reports whether it is usable.
type TransportRequest struct {
	Protocol string                 `json:"protocol"`
	Host     string                 `json:"host"`
	Port     int                    `json:"port"`
	Enabled  *bool                  `json:"enabled"`
	Priority int                    `json:"priority"`
	Metadata map[string]interface{} `json:"metadata"`
}

func validateTransportRequests(requests []TransportRequest, production bool, allowLoopback bool) ([]models.TransportCapability, error) {
	if len(requests) == 0 {
		return nil, fmt.Errorf("at least one transport is required")
	}
	if len(requests) > len(supportedTransportProtocols) {
		return nil, fmt.Errorf("too many transports")
	}
	seen := make(map[string]struct{}, len(requests))
	transports := make([]models.TransportCapability, 0, len(requests))
	for _, request := range requests {
		protocol := strings.ToLower(strings.TrimSpace(request.Protocol))
		if _, ok := supportedTransportProtocols[protocol]; !ok {
			return nil, fmt.Errorf("unsupported transport protocol %q", request.Protocol)
		}
		if _, duplicate := seen[protocol]; duplicate {
			return nil, fmt.Errorf("transport protocol %q is duplicated", protocol)
		}
		seen[protocol] = struct{}{}
		if request.Enabled == nil {
			return nil, fmt.Errorf("transport %q must declare enabled", protocol)
		}
		host, port, err := normalizeAdminServerHost(request.Host, request.Port)
		if err != nil {
			return nil, fmt.Errorf("transport %q: %w", protocol, err)
		}
		if production && !allowLoopback && isLoopbackServerHost(host) {
			return nil, fmt.Errorf("transport %q: loopback hosts are not allowed in production", protocol)
		}
		if request.Priority < 0 || request.Priority > 1000 {
			return nil, fmt.Errorf("transport %q: priority must be between 0 and 1000", protocol)
		}
		if encoded, err := json.Marshal(request.Metadata); err != nil {
			return nil, fmt.Errorf("transport %q: metadata must be JSON", protocol)
		} else if len(encoded) > 8192 {
			return nil, fmt.Errorf("transport %q: metadata must not exceed 8 KiB", protocol)
		}
		transports = append(transports, models.TransportCapability{
			Protocol: protocol, Host: host, Port: port, Enabled: *request.Enabled,
			Priority: request.Priority, HealthStatus: "unknown", Metadata: request.Metadata,
		})
	}
	return transports, nil
}

func enabledServerTransport(server *models.VPNServer, protocol string) (models.TransportCapability, bool) {
	for _, transport := range server.Transports {
		if transport.Protocol == protocol && transport.IsUsable() {
			return transport, true
		}
	}
	return models.TransportCapability{}, false
}

func configuredServerTransport(server *models.VPNServer, protocol string) (models.TransportCapability, bool) {
	for _, transport := range server.Transports {
		if transport.Protocol == protocol && transport.Enabled {
			return transport, true
		}
	}
	return models.TransportCapability{}, false
}

func hasEnabledCertificateTransport(transports []models.TransportCapability) bool {
	for _, transport := range transports {
		if transport.Enabled && (transport.Protocol == "openvpn" || transport.Protocol == "ikev2") {
			return true
		}
	}
	return false
}

package control

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/openvpnhealth"
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
		if protocol == "openvpn" {
			if err := validateOpenVPNMetadata(request.Metadata); err != nil {
				return nil, fmt.Errorf("transport %q: %w", protocol, err)
			}
		}
		if protocol == "ikev2" {
			if err := validateIKEv2Metadata(request.Metadata); err != nil {
				return nil, fmt.Errorf("transport %q: %w", protocol, err)
			}
		}
		transports = append(transports, models.TransportCapability{
			Protocol: protocol, Host: host, Port: port, Enabled: *request.Enabled,
			Priority: request.Priority, HealthStatus: "unknown", Metadata: request.Metadata,
		})
	}
	return transports, nil
}

func validateIKEv2Metadata(metadata map[string]interface{}) error {
	serverName, ok := metadata["server_name"].(string)
	serverName = strings.TrimSpace(serverName)
	if !ok || !validDNSCertificateName(serverName) {
		return fmt.Errorf("metadata.server_name must be a DNS certificate name")
	}
	if metadataStringValue(metadata, "health_file") != "/run/midorivpn-health/ikev2.json" {
		return fmt.Errorf("metadata.health_file must use the private IKEv2 health status file")
	}
	if certified, exists := metadata["certified"]; exists {
		if _, ok := certified.(bool); !ok {
			return fmt.Errorf("metadata.certified must be a boolean")
		}
	}
	dnsValues := metadataStringSlice(metadata["dns"])
	if len(dnsValues) == 0 {
		return fmt.Errorf("metadata.dns must contain at least one IP address")
	}
	for _, value := range dnsValues {
		if net.ParseIP(value) == nil {
			return fmt.Errorf("metadata.dns contains an invalid IP address")
		}
	}
	return nil
}

func validateOpenVPNMetadata(metadata map[string]interface{}) error {
	serverName, ok := metadata["server_name"].(string)
	serverName = strings.TrimSpace(serverName)
	if !ok || !validDNSCertificateName(serverName) {
		return fmt.Errorf("metadata.server_name must be a DNS certificate name")
	}
	healthFile := metadataStringValue(metadata, "health_file")
	if healthFile == "" {
		return fmt.Errorf("metadata.health_file is required")
	}
	if healthFile != openvpnhealth.StatusFile {
		return fmt.Errorf("metadata.health_file must use the private OpenVPN health status file")
	}
	if _, exists := metadata["health_url"]; exists {
		return fmt.Errorf("metadata.health_url is not supported")
	}
	if certified, exists := metadata["certified"]; exists {
		if _, ok := certified.(bool); !ok {
			return fmt.Errorf("metadata.certified must be a boolean")
		}
	}
	dnsValues := metadataStringSlice(metadata["dns"])
	if len(dnsValues) == 0 {
		return fmt.Errorf("metadata.dns must contain at least one IP address")
	}
	for _, value := range dnsValues {
		if net.ParseIP(value) == nil {
			return fmt.Errorf("metadata.dns contains an invalid IP address")
		}
	}
	return nil
}

func validDNSCertificateName(value string) bool {
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
				return false
			}
		}
	}
	return true
}

func metadataStringValue(metadata map[string]interface{}, key string) string {
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func metadataStringSlice(value interface{}) []string {
	result := []string{}
	switch typed := value.(type) {
	case []string:
		result = append(result, typed...)
	case []interface{}:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				result = append(result, strings.TrimSpace(text))
			}
		}
	case string:
		result = strings.FieldsFunc(typed, func(r rune) bool { return r == ',' || r == ' ' })
	}
	return result
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

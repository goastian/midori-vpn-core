package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID  `json:"id"`
	AuthentikUID string     `json:"authentik_uid"`
	Email        string     `json:"email"`
	DisplayName  string     `json:"display_name"`
	Groups       []string   `json:"groups"`
	IsBanned     bool       `json:"is_banned"`
	BannedAt     *time.Time `json:"banned_at,omitempty"`
	BanReason    string     `json:"ban_reason,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type VPNServer struct {
	ID                uuid.UUID             `json:"id"`
	Name              string                `json:"name"`
	Host              string                `json:"host"`
	Endpoint          string                `json:"endpoint"`
	Port              int                   `json:"port"`
	WGPort            int                   `json:"wg_port"`
	PublicKey         string                `json:"public_key"`
	Location          string                `json:"location"`
	CountryCode       string                `json:"country_code"`
	MaxPeers          int                   `json:"max_peers"`
	CurrentPeers      int                   `json:"current_peers"`
	IsActive          bool                  `json:"is_active"`
	SupportsWireGuard bool                  `json:"supports_wireguard"`
	SupportsProxy     bool                  `json:"supports_proxy"`
	SupportsMeshExit  bool                  `json:"supports_mesh_exit"`
	Transports        []TransportCapability `json:"transports,omitempty"`
	CreatedAt         time.Time             `json:"created_at"`
	UpdatedAt         time.Time             `json:"updated_at"`
}

// TransportCapability is the server-advertised contract consumed by clients.
// A transport is never advertised until its backend has passed health checks.
type TransportCapability struct {
	Protocol     string                 `json:"protocol"`
	Host         string                 `json:"host"`
	Port         int                    `json:"port"`
	Enabled      bool                   `json:"enabled"`
	Priority     int                    `json:"priority"`
	HealthStatus string                 `json:"health_status"`
	LastChecked  *time.Time             `json:"last_checked_at,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

func (s *VPNServer) SetTransports(transports []TransportCapability) {
	s.Transports = transports
}

func (t TransportCapability) IsUsable() bool {
	return t.Enabled && t.HealthStatus == "healthy"
}

func (s *VPNServer) ApplyCapabilities() {
	s.SupportsWireGuard = false
	s.SupportsProxy = false
	s.SupportsMeshExit = false
	for _, transport := range s.Transports {
		if !s.IsActive || !transport.IsUsable() {
			continue
		}
		switch transport.Protocol {
		case "wireguard", "wss", "masque":
			s.SupportsWireGuard = true
		case "proxy":
			s.SupportsProxy = true
		}
	}
	s.SupportsMeshExit = s.SupportsProxy
}

type Peer struct {
	ID            uuid.UUID  `json:"id"`
	UserID        uuid.UUID  `json:"user_id"`
	UserEmail     string     `json:"user_email,omitempty"`
	ServerID      uuid.UUID  `json:"server_id"`
	PublicKey     string     `json:"public_key"`
	PresharedKey  string     `json:"preshared_key,omitempty"`
	AssignedIP    string     `json:"assigned_ip"`
	IsActive      bool       `json:"is_active"`
	DeviceName    string     `json:"device_name"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	BytesSent     int64      `json:"bytes_sent"`
	BytesReceived int64      `json:"bytes_received"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

type AuditLog struct {
	ID        uuid.UUID              `json:"id"`
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	UserEmail string                 `json:"user_email,omitempty"`
	Action    string                 `json:"action"`
	Metadata  map[string]interface{} `json:"metadata"`
	IPAddress string                 `json:"ip_address"`
	CreatedAt time.Time              `json:"created_at"`
}

type ConnectionConfig struct {
	PeerID          uuid.UUID `json:"peer_id"`
	PeerIP          string    `json:"peer_ip"`
	ServerPublicKey string    `json:"server_public_key"`
	ServerEndpoint  string    `json:"server_endpoint"`
	PresharedKey    string    `json:"preshared_key,omitempty"`
	PQKEMCiphertext string    `json:"pq_kem_ciphertext,omitempty"`
	DNS             string    `json:"dns"`
	AllowedIPs      string    `json:"allowed_ips"`
}

type AdminStats struct {
	TotalUsers     int   `json:"total_users"`
	TotalServers   int   `json:"total_servers"`
	ActiveServers  int   `json:"active_servers"`
	TotalPeers     int   `json:"total_peers"`
	ActivePeers    int   `json:"active_peers"`
	TotalBytesSent int64 `json:"total_bytes_sent"`
	TotalBytesRecv int64 `json:"total_bytes_received"`
}

type DeviceTypeBreakdown struct {
	Desktop   int `json:"desktop"`
	Extension int `json:"extension"`
	Wireguard int `json:"wireguard"`
}

type UserQuota struct {
	ConnectedDevices int                 `json:"connected_devices"`
	MaxDevices       int                 `json:"max_devices"`
	AvailableDevices int                 `json:"available_devices"`
	PlanSlug         string              `json:"plan_slug"`
	PlanName         string              `json:"plan_name"`
	DevicesByType    DeviceTypeBreakdown `json:"devices_by_type"`
}

type UserProfileResponse struct {
	User
	Quota *UserQuota `json:"quota,omitempty"`
}

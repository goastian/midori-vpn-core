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

type DeviceType string

const (
	DeviceTypeDesktop   DeviceType = "desktop"
	DeviceTypeExtension DeviceType = "extension"
	DeviceTypeManual    DeviceType = "manual"
	DeviceTypeMobile    DeviceType = "mobile"
)

func (t DeviceType) Valid() bool {
	switch t {
	case DeviceTypeDesktop, DeviceTypeExtension, DeviceTypeManual, DeviceTypeMobile:
		return true
	default:
		return false
	}
}

// Device represents one client installation. A nil ClientInstanceID is
// reserved for historical clients that predate persistent installation IDs.
type Device struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	ClientInstanceID *uuid.UUID `json:"client_instance_id"`
	ReportedName     string     `json:"reported_name"`
	Alias            string     `json:"alias"`
	DisplayName      string     `json:"display_name"`
	DeviceType       DeviceType `json:"device_type"`
	AdapterReference string     `json:"adapter_reference"`
	FirstSeenAt      time.Time  `json:"first_seen_at"`
	LastSeenAt       time.Time  `json:"last_seen_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

type DeviceConnection struct {
	ID            uuid.UUID  `json:"id"`
	DeviceID      uuid.UUID  `json:"device_id"`
	ServerID      uuid.UUID  `json:"server_id"`
	Protocol      string     `json:"protocol"`
	PublicKey     string     `json:"public_key"`
	AssignedIP    string     `json:"assigned_ip"`
	IsActive      bool       `json:"is_active"`
	BytesSent     int64      `json:"bytes_sent"`
	BytesReceived int64      `json:"bytes_received"`
	LastHandshake *time.Time `json:"last_handshake"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at"`
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
	if !t.Enabled || t.HealthStatus != "healthy" {
		return false
	}
	if t.Protocol == "openvpn" || t.Protocol == "ikev2" {
		certified, ok := t.Metadata["certified"].(bool)
		return ok && certified
	}
	return true
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
	PresharedKey  string     `json:"-"`
	AssignedIP    string     `json:"assigned_ip"`
	IsActive      bool       `json:"is_active"`
	DeviceName    string     `json:"device_name"`
	DeviceID      *uuid.UUID `json:"device_id,omitempty"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	BytesSent     int64      `json:"bytes_sent"`
	BytesReceived int64      `json:"bytes_received"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

// DeviceCertificate is a client-authentication certificate issued from a CSR.
// Only the public certificate is persisted; the device private key never
// leaves the client that generated it.
type DeviceCertificate struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	ServerID         uuid.UUID  `json:"server_id"`
	DeviceName       string     `json:"device_name"`
	DeviceID         *uuid.UUID `json:"device_id,omitempty"`
	SerialNumber     string     `json:"serial_number"`
	CertificatePEM   string     `json:"certificate_pem,omitempty"`
	PublicKeySHA256  string     `json:"public_key_sha256"`
	NotBefore        time.Time  `json:"not_before"`
	NotAfter         time.Time  `json:"not_after"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
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
	DeviceID        uuid.UUID `json:"device_id"`
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

package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID `json:"id"`
	AuthentikUID string    `json:"authentik_uid"`
	Email        string    `json:"email"`
	Groups       []string  `json:"groups"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type VPNServer struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	Host         string    `json:"host"`
	Port         int       `json:"port"`
	WGPort       int       `json:"wg_port"`
	PublicKey    string    `json:"public_key"`
	CoreToken    string    `json:"-"`
	Location     string    `json:"location"`
	CountryCode  string    `json:"country_code"`
	MaxPeers     int       `json:"max_peers"`
	CurrentPeers int       `json:"current_peers"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Peer struct {
	ID            uuid.UUID  `json:"id"`
	UserID        uuid.UUID  `json:"user_id"`
	ServerID      uuid.UUID  `json:"server_id"`
	PublicKey     string     `json:"public_key"`
	AssignedIP    string     `json:"assigned_ip"`
	IsActive      bool       `json:"is_active"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	BytesSent     int64      `json:"bytes_sent"`
	BytesReceived int64      `json:"bytes_received"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

type AuditLog struct {
	ID        uuid.UUID              `json:"id"`
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	Action    string                 `json:"action"`
	Metadata  map[string]interface{} `json:"metadata"`
	IPAddress string                 `json:"ip_address"`
	CreatedAt time.Time              `json:"created_at"`
}

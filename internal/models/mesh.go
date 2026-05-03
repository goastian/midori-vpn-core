package models

import (
	"time"

	"github.com/google/uuid"
)

// MeshNetwork is a named private overlay network. Members within a mesh can
// reach each other using their assigned mesh IPs routed through the VPN servers.
type MeshNetwork struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	OwnerID     uuid.UUID  `json:"owner_id"`
	Subnet      string     `json:"subnet"`
	// InviteCode is only returned to the owner and to the invite endpoint.
	InviteCode       string     `json:"invite_code,omitempty"`
	InviteExpiresAt  *time.Time `json:"invite_expires_at,omitempty"`
	MaxMembers  int       `json:"max_members"`
	IsActive    bool      `json:"is_active"`
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// MeshMember links a user (and optionally their active VPN peer) to a
// MeshNetwork, with a dedicated IP address within the mesh subnet.
type MeshMember struct {
	ID          uuid.UUID  `json:"id"`
	MeshID      uuid.UUID  `json:"mesh_id"`
	UserID      uuid.UUID  `json:"user_id"`
	PeerID      *uuid.UUID `json:"peer_id,omitempty"`
	MeshIP      string     `json:"mesh_ip"`
	DisplayName string     `json:"display_name,omitempty"`
	JoinedAt    time.Time  `json:"joined_at"`
}

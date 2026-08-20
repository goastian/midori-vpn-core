-- =============================================================================
-- MidoriVPN Consolidated Database Schema (PostgreSQL 16+)
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Users Table (OIDC / Authentik identity)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    authentik_uid VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) DEFAULT '',
    groups TEXT[] DEFAULT '{}',
    is_banned BOOLEAN NOT NULL DEFAULT FALSE,
    banned_at TIMESTAMPTZ,
    ban_reason TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_authentik_uid ON users(authentik_uid);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_is_banned ON users(is_banned) WHERE is_banned = TRUE;

-- 2. VPN Servers Table
CREATE TABLE IF NOT EXISTS vpn_servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    host VARCHAR(255) NOT NULL,
    endpoint VARCHAR(255) NOT NULL DEFAULT '',
    port INT NOT NULL DEFAULT 8085,
    wg_port INT NOT NULL DEFAULT 51820,
    public_key VARCHAR(64) NOT NULL,
    core_token VARCHAR(255) NOT NULL,
    location VARCHAR(100) NOT NULL,
    country_code VARCHAR(10) NOT NULL,
    max_peers INT NOT NULL DEFAULT 100,
    current_peers INT NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    proxy_port INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vpn_servers_active_peers ON vpn_servers(is_active, current_peers, max_peers);
CREATE INDEX IF NOT EXISTS idx_vpn_servers_host ON vpn_servers(host);

-- 3. Peers Table (WireGuard Client Allocations)
CREATE TABLE IF NOT EXISTS peers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id UUID NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    public_key VARCHAR(64) NOT NULL,
    preshared_key VARCHAR(64),
    assigned_ip VARCHAR(50) NOT NULL,
    device_name VARCHAR(64) NOT NULL DEFAULT 'device',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_handshake TIMESTAMPTZ,
    bytes_sent BIGINT NOT NULL DEFAULT 0,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_peers_user_id ON peers(user_id);
CREATE INDEX IF NOT EXISTS idx_peers_server_id ON peers(server_id);
CREATE INDEX IF NOT EXISTS idx_peers_user_active ON peers(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_peers_server_active ON peers(server_id, is_active);
CREATE INDEX IF NOT EXISTS idx_peers_user_pubkey_active ON peers(user_id, public_key) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_peers_active_stale ON peers(is_active, last_handshake, created_at) WHERE is_active = TRUE;

-- 4. Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created ON audit_logs(action, created_at DESC);

-- 5. Mesh Networks Table
CREATE TABLE IF NOT EXISTS mesh_networks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    subnet VARCHAR(50) NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    community_name VARCHAR(100) DEFAULT '',
    country_code VARCHAR(10) DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mesh_networks_owner ON mesh_networks(owner_id);
CREATE INDEX IF NOT EXISTS idx_mesh_networks_public ON mesh_networks(is_public) WHERE is_public = TRUE;

-- 6. Mesh Members Table
CREATE TABLE IF NOT EXISTS mesh_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mesh_id UUID NOT NULL REFERENCES mesh_networks(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mesh_ip VARCHAR(50) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'member',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(mesh_id, user_id),
    UNIQUE(mesh_id, mesh_ip)
);

CREATE INDEX IF NOT EXISTS idx_mesh_members_mesh_user ON mesh_members(mesh_id, user_id);

-- 7. Mesh Invites Table
CREATE TABLE IF NOT EXISTS mesh_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mesh_id UUID NOT NULL REFERENCES mesh_networks(id) ON DELETE CASCADE,
    code VARCHAR(64) UNIQUE NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    max_uses INT NOT NULL DEFAULT 1,
    uses INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mesh_invites_code ON mesh_invites(code);

-- 8. Mesh Sessions Table
CREATE TABLE IF NOT EXISTS mesh_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mesh_id UUID NOT NULL REFERENCES mesh_networks(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    peer_id UUID REFERENCES peers(id) ON DELETE SET NULL,
    public_key VARCHAR(64) NOT NULL,
    public_ip VARCHAR(100) DEFAULT '',
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(mesh_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_mesh_sessions_mesh_user ON mesh_sessions(mesh_id, user_id);

-- 9. Exit Nodes Table
CREATE TABLE IF NOT EXISTS exit_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    city VARCHAR(100) NOT NULL DEFAULT '',
    country VARCHAR(100) NOT NULL DEFAULT '',
    country_code VARCHAR(10) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    supports_wireguard BOOLEAN NOT NULL DEFAULT TRUE,
    supports_proxy BOOLEAN NOT NULL DEFAULT TRUE,
    supports_mesh_exit BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_exit_nodes_active ON exit_nodes(is_active) WHERE is_active = TRUE;

-- 10. Trusted Extension Origins Table
CREATE TABLE IF NOT EXISTS trusted_extension_origins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    origin VARCHAR(255) UNIQUE NOT NULL,
    description VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 11. IP Country Cache Table
CREATE TABLE IF NOT EXISTS ip_country_cache (
    ip VARCHAR(45) PRIMARY KEY,
    country_code VARCHAR(10) NOT NULL,
    city VARCHAR(100) NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Midori VPN v2.0.0 Canonical Consolidated PostgreSQL Schema
-- Generated from migrations 000001 - 000009

BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- Table: users
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    authentik_uid  TEXT        NOT NULL UNIQUE,
    email          TEXT        NOT NULL DEFAULT '',
    display_name   TEXT        NOT NULL DEFAULT '',
    groups         TEXT[]      NOT NULL DEFAULT '{}',
    is_banned      BOOLEAN     NOT NULL DEFAULT FALSE,
    banned_at      TIMESTAMPTZ,
    ban_reason     TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Table: vpn_servers
-- ============================================================
CREATE TABLE IF NOT EXISTS vpn_servers (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT        NOT NULL,
    host           TEXT        NOT NULL,
    endpoint       TEXT        NOT NULL DEFAULT '',
    port           INTEGER     NOT NULL DEFAULT 443,
    wg_port        INTEGER     NOT NULL DEFAULT 51820,
    public_key     TEXT        NOT NULL DEFAULT '',
    location       TEXT        NOT NULL DEFAULT '',
    country_code   TEXT        NOT NULL DEFAULT '',
    max_peers      INTEGER     NOT NULL DEFAULT 100,
    current_peers  INTEGER     NOT NULL DEFAULT 0,
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vpn_servers_active ON vpn_servers (is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_vpn_servers_country_active ON vpn_servers (country_code, is_active) WHERE is_active = TRUE;

-- ============================================================
-- Table: vpn_server_transports
-- ============================================================
CREATE TABLE IF NOT EXISTS vpn_server_transports (
    server_id       UUID        NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    protocol        TEXT        NOT NULL,
    endpoint        TEXT        NOT NULL,
    port            INTEGER     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    enabled         BOOLEAN     NOT NULL DEFAULT FALSE,
    priority        INTEGER     NOT NULL DEFAULT 0,
    health_status   TEXT        NOT NULL DEFAULT 'unknown'
                                CHECK (health_status IN ('unknown', 'healthy', 'degraded', 'disabled')),
    metadata        JSONB       NOT NULL DEFAULT '{}'::JSONB,
    last_checked_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_id, protocol),
    CONSTRAINT chk_vpn_server_transports_protocol
        CHECK (protocol IN ('wireguard', 'wss', 'masque', 'openvpn', 'ikev2', 'proxy'))
);

CREATE INDEX IF NOT EXISTS idx_vpn_server_transports_enabled
    ON vpn_server_transports (protocol, priority DESC)
    WHERE enabled = TRUE;

-- ============================================================
-- Table: peers
-- ============================================================
CREATE TABLE IF NOT EXISTS peers (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id      UUID        NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    public_key     TEXT        NOT NULL,
    preshared_key  TEXT        NOT NULL DEFAULT '',
    assigned_ip    TEXT        NOT NULL,
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    device_name    TEXT        NOT NULL DEFAULT '',
    last_handshake TIMESTAMPTZ,
    bytes_sent     BIGINT      NOT NULL DEFAULT 0,
    bytes_received BIGINT      NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_peers_active_server_assigned_ip ON peers (server_id, assigned_ip) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_peers_public_key ON peers (public_key);
CREATE INDEX IF NOT EXISTS idx_peers_is_active ON peers (is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_peers_assigned_ip ON peers (assigned_ip);
CREATE INDEX IF NOT EXISTS idx_peers_created_at ON peers (created_at DESC);

-- ============================================================
-- Table: mesh_networks
-- ============================================================
CREATE TABLE IF NOT EXISTS mesh_networks (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT        NOT NULL,
    description       TEXT        NOT NULL DEFAULT '',
    subnet            TEXT        NOT NULL,
    owner_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invite_code       TEXT        NOT NULL UNIQUE,
    invite_expires_at TIMESTAMPTZ,
    max_members       INTEGER     NOT NULL DEFAULT 10,
    member_count      INTEGER     NOT NULL DEFAULT 0,
    is_active         BOOLEAN     NOT NULL DEFAULT TRUE,
    is_session        BOOLEAN     NOT NULL DEFAULT FALSE,
    is_public         BOOLEAN     NOT NULL DEFAULT FALSE,
    country_code      TEXT        NOT NULL DEFAULT '',
    public_ip         TEXT        NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mesh_networks_owner ON mesh_networks (owner_id);
CREATE INDEX IF NOT EXISTS idx_mesh_networks_invite ON mesh_networks (invite_code);
CREATE INDEX IF NOT EXISTS idx_mesh_networks_session ON mesh_networks (is_session) WHERE is_session = TRUE;
CREATE INDEX IF NOT EXISTS idx_mesh_networks_public ON mesh_networks (is_public) WHERE is_public = TRUE;

-- ============================================================
-- Table: mesh_members
-- ============================================================
CREATE TABLE IF NOT EXISTS mesh_members (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    mesh_id        UUID        NOT NULL REFERENCES mesh_networks(id) ON DELETE CASCADE,
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key     TEXT        NOT NULL,
    preshared_key  TEXT        NOT NULL DEFAULT '',
    assigned_ip    TEXT        NOT NULL,
    endpoint       TEXT        NOT NULL DEFAULT '',
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_mesh_members_mesh_ip UNIQUE (mesh_id, assigned_ip),
    CONSTRAINT uq_mesh_members_mesh_user UNIQUE (mesh_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_mesh_members_user_active ON mesh_members (user_id, is_active) WHERE is_active = TRUE;

-- ============================================================
-- Table: exit_nodes
-- ============================================================
CREATE TABLE IF NOT EXISTS exit_nodes (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    mesh_id        UUID        NOT NULL REFERENCES mesh_networks(id) ON DELETE CASCADE,
    member_id      UUID        NOT NULL REFERENCES mesh_members(id) ON DELETE CASCADE,
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    country_code   TEXT        NOT NULL DEFAULT '',
    public_ip      TEXT        NOT NULL DEFAULT '',
    allow_traffic  BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_exit_nodes_mesh UNIQUE (mesh_id)
);

CREATE INDEX IF NOT EXISTS idx_exit_nodes_mesh_active ON exit_nodes (mesh_id, is_active) WHERE is_active = TRUE;

-- ============================================================
-- Table: ip_country_cache
-- ============================================================
CREATE TABLE IF NOT EXISTS ip_country_cache (
    ip             TEXT        PRIMARY KEY,
    country_code   TEXT        NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Table: trusted_extension_origins
-- ============================================================
CREATE TABLE IF NOT EXISTS trusted_extension_origins (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    origin         TEXT        NOT NULL UNIQUE,
    revoked        BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Table: audit_logs
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID        REFERENCES users(id) ON DELETE SET NULL,
    action         TEXT        NOT NULL,
    resource_type  TEXT        NOT NULL DEFAULT '',
    resource_id    TEXT        NOT NULL DEFAULT '',
    ip_address     TEXT        NOT NULL DEFAULT '',
    user_agent     TEXT        NOT NULL DEFAULT '',
    metadata       JSONB       NOT NULL DEFAULT '{}'::JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC);

COMMIT;

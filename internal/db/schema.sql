-- Midori VPN v2.0.0 Canonical Consolidated PostgreSQL Schema
-- Generated from migrations 000001 - 000015

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
    draining_at    TIMESTAMPTZ,
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
-- Table: devices
-- ============================================================
CREATE TABLE IF NOT EXISTS devices (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_instance_id  UUID,
    reported_name       TEXT        NOT NULL,
    alias               TEXT,
    device_type         TEXT        NOT NULL,
    adapter_reference   TEXT,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at          TIMESTAMPTZ,
    CONSTRAINT uq_devices_user_client_instance UNIQUE (user_id, client_instance_id),
    CONSTRAINT uq_devices_id_user UNIQUE (id, user_id),
    CONSTRAINT chk_devices_reported_name CHECK (length(reported_name) BETWEEN 1 AND 64),
    CONSTRAINT chk_devices_alias CHECK (alias IS NULL OR length(alias) BETWEEN 1 AND 64),
    CONSTRAINT chk_devices_type CHECK (device_type IN ('desktop', 'extension', 'manual', 'mobile')),
    CONSTRAINT chk_devices_adapter_reference CHECK (
        adapter_reference IS NULL OR adapter_reference ~ '^net-v1:[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT chk_devices_seen_order CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT chk_devices_revoked_order CHECK (revoked_at IS NULL OR revoked_at >= first_seen_at)
);

CREATE INDEX IF NOT EXISTS idx_devices_user_last_seen ON devices (user_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_devices_adapter_reference ON devices (adapter_reference) WHERE adapter_reference IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_devices_user_active ON devices (user_id, device_type) WHERE revoked_at IS NULL;

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
    device_id      UUID,
    last_handshake TIMESTAMPTZ,
    bytes_sent     BIGINT      NOT NULL DEFAULT 0,
    bytes_received BIGINT      NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ,
    CONSTRAINT fk_peers_device_owner
        FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT chk_peers_active_device CHECK (is_active = FALSE OR device_id IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_peers_active_server_assigned_ip ON peers (server_id, assigned_ip) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_peers_public_key ON peers (public_key);
CREATE INDEX IF NOT EXISTS idx_peers_is_active ON peers (is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_peers_assigned_ip ON peers (assigned_ip);
CREATE INDEX IF NOT EXISTS idx_peers_created_at ON peers (created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_peers_active_device ON peers (device_id) WHERE is_active = TRUE AND device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_peers_device_created ON peers (device_id, created_at DESC) WHERE device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_peers_user_active ON peers (user_id) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_peers_server_active ON peers (server_id) WHERE is_active = TRUE;

-- ============================================================
-- Table: peer_operations
-- ============================================================
CREATE TABLE IF NOT EXISTS peer_operations (
    id                  UUID        PRIMARY KEY,
    action              TEXT        NOT NULL CHECK (action IN ('connect', 'replace', 'disconnect')),
    state               TEXT        NOT NULL CHECK (state IN ('pending', 'core_applied', 'completed', 'cleanup_pending', 'failed')),
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id           UUID        NOT NULL,
    server_id           UUID        NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    public_key          TEXT        NOT NULL CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    preshared_key       TEXT        NOT NULL DEFAULT '',
    pq_kem_ciphertext   TEXT        NOT NULL DEFAULT '',
    previous_peer_id    UUID        REFERENCES peers(id) ON DELETE SET NULL,
    previous_operation_id UUID,
    assigned_ip         TEXT,
    capacity_reserved   BOOLEAN     NOT NULL DEFAULT FALSE,
    attempts            INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error          TEXT        NOT NULL DEFAULT '' CHECK (length(last_error) <= 1024),
    core_applied_at     TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_peer_operations_device_owner
        FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT chk_peer_operations_applied_data CHECK (
        state NOT IN ('core_applied', 'completed', 'cleanup_pending')
        OR (assigned_ip IS NOT NULL AND core_applied_at IS NOT NULL)
    ),
    CONSTRAINT chk_peer_operations_completion CHECK (
        state NOT IN ('completed', 'cleanup_pending') OR completed_at IS NOT NULL
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_peer_operations_live_device
    ON peer_operations (device_id) WHERE state IN ('pending', 'core_applied', 'cleanup_pending');
CREATE UNIQUE INDEX IF NOT EXISTS uq_peer_operations_live_key
    ON peer_operations (public_key) WHERE state IN ('pending', 'core_applied', 'cleanup_pending');
CREATE INDEX IF NOT EXISTS idx_peer_operations_state_updated ON peer_operations (state, updated_at);
CREATE INDEX IF NOT EXISTS idx_peer_operations_user_created ON peer_operations (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_peer_operations_server_state ON peer_operations (server_id, state);
CREATE INDEX IF NOT EXISTS idx_peer_operations_user_live
    ON peer_operations (user_id) WHERE state IN ('pending', 'core_applied', 'cleanup_pending');
CREATE INDEX IF NOT EXISTS idx_peer_operations_previous_peer_live
    ON peer_operations (previous_peer_id)
    WHERE previous_peer_id IS NOT NULL
      AND state IN ('pending', 'core_applied', 'cleanup_pending');

ALTER TABLE peers
    ADD COLUMN provision_operation_id UUID,
    ADD CONSTRAINT fk_peers_provision_operation
        FOREIGN KEY (provision_operation_id) REFERENCES peer_operations(id)
        DEFERRABLE INITIALLY DEFERRED;
CREATE UNIQUE INDEX IF NOT EXISTS uq_peers_provision_operation
    ON peers (provision_operation_id) WHERE provision_operation_id IS NOT NULL;

CREATE FUNCTION prevent_delete_with_live_peer_operation()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'users' AND EXISTS (
        SELECT 1 FROM peer_operations WHERE user_id = OLD.id
        AND state IN ('pending', 'core_applied', 'cleanup_pending')
    ) THEN
        RAISE EXCEPTION 'user has a pending peer operation' USING ERRCODE = '55000';
    ELSIF TG_TABLE_NAME = 'devices' AND EXISTS (
        SELECT 1 FROM peer_operations WHERE device_id = OLD.id
        AND state IN ('pending', 'core_applied', 'cleanup_pending')
    ) THEN
        RAISE EXCEPTION 'device has a pending peer operation' USING ERRCODE = '55000';
    ELSIF TG_TABLE_NAME = 'vpn_servers' AND EXISTS (
        SELECT 1 FROM peer_operations WHERE server_id = OLD.id
        AND state IN ('pending', 'core_applied', 'cleanup_pending')
    ) THEN
        RAISE EXCEPTION 'server has a pending peer operation' USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_users_live_peer_operation BEFORE DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION prevent_delete_with_live_peer_operation();
CREATE TRIGGER trg_devices_live_peer_operation BEFORE DELETE ON devices
    FOR EACH ROW EXECUTE FUNCTION prevent_delete_with_live_peer_operation();
CREATE TRIGGER trg_servers_live_peer_operation BEFORE DELETE ON vpn_servers
    FOR EACH ROW EXECUTE FUNCTION prevent_delete_with_live_peer_operation();

-- ============================================================
-- Table: device_certificates
-- ============================================================
CREATE TABLE IF NOT EXISTS device_certificates (
    id                  UUID        PRIMARY KEY,
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id           UUID        NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    device_name         TEXT        NOT NULL,
    device_id           UUID,
    serial_number       TEXT        NOT NULL UNIQUE,
    certificate_pem     TEXT        NOT NULL,
    public_key_sha256   TEXT        NOT NULL,
    not_before          TIMESTAMPTZ NOT NULL,
    not_after           TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   TEXT        NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (length(device_name) BETWEEN 1 AND 64),
    CHECK (length(serial_number) BETWEEN 2 AND 64),
    CHECK (length(public_key_sha256) = 64),
    CHECK (not_after > not_before),
    CONSTRAINT fk_device_certificates_device_owner
        FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT chk_device_certificates_current_device
        CHECK (revoked_at IS NOT NULL OR device_id IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_device_certificates_active_device_id
    ON device_certificates (device_id, server_id)
    WHERE revoked_at IS NULL AND device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_device_certificates_user_created
    ON device_certificates (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_certificates_active_expiry
    ON device_certificates (not_after)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_device_certificates_revoked
    ON device_certificates (revoked_at)
    WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_device_certificates_device_created
    ON device_certificates (device_id, created_at DESC)
    WHERE device_id IS NOT NULL;

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

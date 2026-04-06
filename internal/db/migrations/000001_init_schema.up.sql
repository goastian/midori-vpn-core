-- 000001_init_schema.up.sql
-- Initial schema: users, vpn_servers, peers, audit_logs

BEGIN;

-- ============================================================
-- Table: users
-- ============================================================
CREATE TABLE users (
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
CREATE TABLE vpn_servers (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT        NOT NULL,
    host           TEXT        NOT NULL,
    port           INTEGER     NOT NULL DEFAULT 443,
    wg_port        INTEGER     NOT NULL DEFAULT 51820,
    public_key     TEXT        NOT NULL DEFAULT '',
    core_token     TEXT        NOT NULL DEFAULT '',
    location       TEXT        NOT NULL DEFAULT '',
    country_code   TEXT        NOT NULL DEFAULT '',
    max_peers      INTEGER     NOT NULL DEFAULT 100,
    current_peers  INTEGER     NOT NULL DEFAULT 0,
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vpn_servers_active ON vpn_servers (is_active) WHERE is_active = TRUE;

-- ============================================================
-- Table: peers
-- ============================================================
CREATE TABLE peers (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id      UUID        NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    public_key     TEXT        NOT NULL,
    assigned_ip    TEXT        NOT NULL,
    is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
    device_name    TEXT        NOT NULL DEFAULT '',
    last_handshake TIMESTAMPTZ,
    bytes_sent     BIGINT      NOT NULL DEFAULT 0,
    bytes_received BIGINT      NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ
);

CREATE INDEX idx_peers_user_id        ON peers (user_id);
CREATE INDEX idx_peers_server_id      ON peers (server_id);
CREATE INDEX idx_peers_active_server  ON peers (server_id) WHERE is_active = TRUE;

-- ============================================================
-- Table: audit_logs
-- ============================================================
CREATE TABLE audit_logs (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        REFERENCES users(id) ON DELETE SET NULL,
    action     TEXT        NOT NULL,
    metadata   JSONB       NOT NULL DEFAULT '{}',
    ip_address TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id    ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_action     ON audit_logs (action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);

COMMIT;

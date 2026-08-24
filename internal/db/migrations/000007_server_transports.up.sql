BEGIN;

CREATE TABLE vpn_server_transports (
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

CREATE INDEX idx_vpn_server_transports_enabled
    ON vpn_server_transports (protocol, priority DESC)
    WHERE enabled = TRUE;

INSERT INTO vpn_server_transports (server_id, protocol, endpoint, port, enabled, priority)
SELECT id, 'wireguard', CASE WHEN endpoint = '' THEN host ELSE endpoint END, wg_port,
       is_active AND public_key <> '', 100
FROM vpn_servers
WHERE wg_port BETWEEN 1 AND 65535
ON CONFLICT (server_id, protocol) DO NOTHING;

INSERT INTO vpn_server_transports (server_id, protocol, endpoint, port, enabled, priority)
SELECT id, 'wss', CASE WHEN wss_host = '' THEN host ELSE wss_host END, wss_port,
       is_active AND wss_tunnel_enabled, 90
FROM vpn_servers
WHERE wss_port BETWEEN 1 AND 65535
ON CONFLICT (server_id, protocol) DO NOTHING;

INSERT INTO vpn_server_transports (server_id, protocol, endpoint, port, enabled, priority)
SELECT id, 'proxy', host, proxy_port, is_active, 0
FROM vpn_servers
WHERE proxy_port BETWEEN 1 AND 65535
ON CONFLICT (server_id, protocol) DO NOTHING;

COMMIT;

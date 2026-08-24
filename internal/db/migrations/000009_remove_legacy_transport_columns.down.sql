BEGIN;

ALTER TABLE vpn_servers
    ADD COLUMN IF NOT EXISTS proxy_port INTEGER NOT NULL DEFAULT 8443,
    ADD COLUMN IF NOT EXISTS proxy_scheme VARCHAR(10) NOT NULL DEFAULT 'https',
    ADD COLUMN IF NOT EXISTS wss_tunnel_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS wss_host TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS wss_port INTEGER NOT NULL DEFAULT 443;

UPDATE vpn_servers s
SET proxy_port = t.port
FROM vpn_server_transports t
WHERE t.server_id = s.id AND t.protocol = 'proxy';

UPDATE vpn_servers s
SET wss_tunnel_enabled = t.enabled,
    wss_host = t.endpoint,
    wss_port = t.port
FROM vpn_server_transports t
WHERE t.server_id = s.id AND t.protocol = 'wss';

ALTER TABLE vpn_servers
    ADD CONSTRAINT chk_vpn_servers_proxy_scheme CHECK (proxy_scheme = 'https'),
    ADD CONSTRAINT chk_vpn_servers_wss_port CHECK (wss_port BETWEEN 1 AND 65535);

COMMIT;

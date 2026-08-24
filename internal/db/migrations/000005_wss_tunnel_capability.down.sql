BEGIN;

ALTER TABLE vpn_servers
    DROP CONSTRAINT IF EXISTS chk_vpn_servers_wss_port,
    DROP COLUMN IF EXISTS wss_port,
    DROP COLUMN IF EXISTS wss_host,
    DROP COLUMN IF EXISTS wss_tunnel_enabled;

COMMIT;

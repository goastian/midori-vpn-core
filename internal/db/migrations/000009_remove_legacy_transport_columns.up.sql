BEGIN;

-- vpn_server_transports is the only advertised transport contract since v2.
-- Refuse to discard the old columns unless every active server has an explicit
-- WireGuard transport, so an incomplete rollout cannot silently remove access.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM vpn_servers s
        WHERE s.is_active
          AND NOT EXISTS (
              SELECT 1 FROM vpn_server_transports t
              WHERE t.server_id = s.id AND t.protocol = 'wireguard'
          )
    ) THEN
        RAISE EXCEPTION 'active VPN servers must have an explicit WireGuard transport before migration 9';
    END IF;
END $$;

ALTER TABLE vpn_servers
    DROP CONSTRAINT IF EXISTS chk_vpn_servers_proxy_scheme,
    DROP CONSTRAINT IF EXISTS chk_vpn_servers_wss_port,
    DROP COLUMN IF EXISTS proxy_port,
    DROP COLUMN IF EXISTS proxy_scheme,
    DROP COLUMN IF EXISTS wss_tunnel_enabled,
    DROP COLUMN IF EXISTS wss_host,
    DROP COLUMN IF EXISTS wss_port;

COMMIT;

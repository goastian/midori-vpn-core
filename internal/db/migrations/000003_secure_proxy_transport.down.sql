BEGIN;

ALTER TABLE vpn_servers
    DROP CONSTRAINT IF EXISTS chk_vpn_servers_proxy_scheme;

ALTER TABLE vpn_servers
    ALTER COLUMN proxy_scheme SET DEFAULT 'https',
    ALTER COLUMN proxy_port SET DEFAULT 443;

COMMIT;

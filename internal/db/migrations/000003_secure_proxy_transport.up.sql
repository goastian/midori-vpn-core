BEGIN;

UPDATE vpn_servers
SET proxy_scheme = 'https'
WHERE proxy_scheme IS NULL OR proxy_scheme <> 'https';

UPDATE vpn_servers
SET proxy_port = 8443
WHERE proxy_port = 443;

ALTER TABLE vpn_servers
    ALTER COLUMN proxy_scheme SET DEFAULT 'https',
    ALTER COLUMN proxy_port SET DEFAULT 8443;

ALTER TABLE vpn_servers
    DROP CONSTRAINT IF EXISTS chk_vpn_servers_proxy_scheme;

ALTER TABLE vpn_servers
    ADD CONSTRAINT chk_vpn_servers_proxy_scheme
    CHECK (proxy_scheme = 'https');

COMMIT;

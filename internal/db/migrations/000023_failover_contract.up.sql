-- Persist the public client probe endpoint and the reason that initiated a
-- connection. Existing servers remain deliberately ineligible for the new
-- candidate API until an administrator assigns an explicit HTTPS probe URL.

BEGIN;

ALTER TABLE vpn_servers
    ADD COLUMN probe_url TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT chk_vpn_servers_probe_url CHECK (
        probe_url = ''
        OR (
            position('@' IN probe_url) = 0
            AND probe_url ~ '^https://[^/?#[:space:]]+(/\.well-known/midorivpn/edge-health)$'
        )
    );

ALTER TABLE peer_operations
    ADD COLUMN connection_reason TEXT NOT NULL DEFAULT 'user',
    ADD CONSTRAINT chk_peer_operations_connection_reason CHECK (
        connection_reason IN ('user', 'automatic_failover')
    );

COMMIT;

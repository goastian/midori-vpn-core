BEGIN;

ALTER TABLE peer_operations
    DROP CONSTRAINT chk_peer_operations_connection_reason,
    DROP COLUMN connection_reason;

ALTER TABLE vpn_servers
    DROP CONSTRAINT chk_vpn_servers_probe_url,
    DROP COLUMN probe_url;

COMMIT;

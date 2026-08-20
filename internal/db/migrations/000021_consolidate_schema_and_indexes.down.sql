-- 000021_consolidate_schema_and_indexes.down.sql
BEGIN;
DROP INDEX IF EXISTS idx_mesh_members_exit_node;
DROP INDEX IF EXISTS idx_vpn_servers_country_active;
ALTER TABLE vpn_servers DROP COLUMN IF EXISTS proxy_scheme;
ALTER TABLE vpn_servers ALTER COLUMN proxy_port SET DEFAULT 8888;
COMMIT;

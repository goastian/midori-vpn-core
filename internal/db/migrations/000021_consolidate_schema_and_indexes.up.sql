-- 000021_consolidate_schema_and_indexes.up.sql
-- Consolidate HTTPS proxy support and optimize high-concurrency lookup indexes

BEGIN;

-- 1. Consolidar esquema HTTPS en vpn_servers
ALTER TABLE vpn_servers ADD COLUMN IF NOT EXISTS proxy_scheme VARCHAR(10) NOT NULL DEFAULT 'https';
ALTER TABLE vpn_servers ALTER COLUMN proxy_port SET DEFAULT 443;
UPDATE vpn_servers SET proxy_port = 443, proxy_scheme = 'https' WHERE proxy_port = 8888 OR proxy_port IS NULL;

-- 2. Consolidar e indexar consultas frecuentes
CREATE INDEX IF NOT EXISTS idx_vpn_servers_country_active ON vpn_servers (country_code, is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_mesh_members_exit_node ON mesh_members (mesh_id, is_exit_node) WHERE is_exit_node = TRUE;

COMMIT;

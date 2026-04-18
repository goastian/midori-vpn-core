-- 000003_server_endpoint.down.sql
ALTER TABLE vpn_servers DROP COLUMN IF EXISTS endpoint;

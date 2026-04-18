-- 000003_server_endpoint.up.sql
-- Add separate public endpoint for WireGuard (distinct from core API host)
ALTER TABLE vpn_servers ADD COLUMN IF NOT EXISTS endpoint TEXT NOT NULL DEFAULT '';

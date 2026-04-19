-- 000005_proxy_port.up.sql
-- Add proxy_port column to vpn_servers for the HTTP CONNECT proxy
ALTER TABLE vpn_servers ADD COLUMN IF NOT EXISTS proxy_port INTEGER NOT NULL DEFAULT 8888;

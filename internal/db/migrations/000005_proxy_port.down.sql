-- 000005_proxy_port.down.sql
ALTER TABLE vpn_servers DROP COLUMN IF EXISTS proxy_port;

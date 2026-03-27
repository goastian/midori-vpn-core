-- 000001_init_schema.down.sql
-- Drop all tables in reverse dependency order

BEGIN;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS peers;
DROP TABLE IF EXISTS vpn_servers;
DROP TABLE IF EXISTS users;

COMMIT;

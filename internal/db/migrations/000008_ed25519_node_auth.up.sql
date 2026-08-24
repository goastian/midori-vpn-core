BEGIN;

ALTER TABLE vpn_servers DROP COLUMN core_token;

COMMIT;

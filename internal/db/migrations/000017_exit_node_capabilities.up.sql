ALTER TABLE mesh_members
    ADD COLUMN IF NOT EXISTS proxy_scheme TEXT NOT NULL DEFAULT 'http-connect',
    ADD COLUMN IF NOT EXISTS supports_tcp  BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS supports_udp  BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE user_exit_node
    ADD COLUMN IF NOT EXISTS proxy_scheme TEXT NOT NULL DEFAULT 'http-connect',
    ADD COLUMN IF NOT EXISTS supports_tcp  BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS supports_udp  BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE mesh_members
SET proxy_scheme = 'http-connect'
WHERE proxy_scheme = '';

UPDATE user_exit_node
SET proxy_scheme = 'http-connect'
WHERE proxy_scheme = '';

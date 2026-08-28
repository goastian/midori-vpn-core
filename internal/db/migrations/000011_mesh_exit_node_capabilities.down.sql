BEGIN;

ALTER TABLE user_exit_node
    DROP CONSTRAINT IF EXISTS chk_user_exit_node_proxy_scheme,
    DROP COLUMN IF EXISTS supports_udp,
    DROP COLUMN IF EXISTS supports_tcp,
    DROP COLUMN IF EXISTS proxy_scheme;

ALTER TABLE mesh_members
    DROP CONSTRAINT IF EXISTS chk_mesh_members_proxy_scheme,
    DROP COLUMN IF EXISTS supports_udp,
    DROP COLUMN IF EXISTS supports_tcp,
    DROP COLUMN IF EXISTS proxy_scheme;

COMMIT;

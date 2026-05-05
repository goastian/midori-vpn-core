ALTER TABLE user_exit_node
    DROP COLUMN IF EXISTS supports_udp,
    DROP COLUMN IF EXISTS supports_tcp,
    DROP COLUMN IF EXISTS proxy_scheme;

ALTER TABLE mesh_members
    DROP COLUMN IF EXISTS supports_udp,
    DROP COLUMN IF EXISTS supports_tcp,
    DROP COLUMN IF EXISTS proxy_scheme;

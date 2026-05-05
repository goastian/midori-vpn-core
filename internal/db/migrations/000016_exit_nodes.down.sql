DROP TABLE IF EXISTS user_exit_node;
ALTER TABLE mesh_members
    DROP COLUMN IF EXISTS is_exit_node,
    DROP COLUMN IF EXISTS proxy_port;

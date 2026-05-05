-- Add exit-node capability columns to mesh_members
ALTER TABLE mesh_members
    ADD COLUMN IF NOT EXISTS is_exit_node  BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS proxy_port    INT      NOT NULL DEFAULT 0;

-- Track which exit node each user has selected
CREATE TABLE IF NOT EXISTS user_exit_node (
    user_id     UUID        PRIMARY KEY,
    mesh_ip     TEXT        NOT NULL,
    proxy_port  INT         NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

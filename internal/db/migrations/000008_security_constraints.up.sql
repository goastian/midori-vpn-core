BEGIN;

-- Validate that assigned_ip values look like a proper CIDR string.
-- This prevents malformed values being stored that could cause parsing
-- failures or unexpected behaviour in the IP pool logic.
ALTER TABLE peers ADD CONSTRAINT check_assigned_ip
    CHECK (assigned_ip ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$');

-- Composite index to speed up audit log queries filtered by action and sorted
-- by time (e.g. "last N events of type X").
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created
    ON audit_logs (action, created_at DESC);

COMMIT;

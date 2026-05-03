BEGIN;

DROP INDEX IF EXISTS idx_audit_logs_action_created;

ALTER TABLE peers DROP CONSTRAINT IF EXISTS check_assigned_ip;

COMMIT;

-- 000002_billing_and_quotas.down.sql
BEGIN;

ALTER TABLE peers DROP COLUMN IF EXISTS max_speed_kbps;
ALTER TABLE peers DROP COLUMN IF EXISTS is_throttled;

DROP TABLE IF EXISTS user_bandwidth_usage;
DROP TABLE IF EXISTS user_subscriptions;

COMMIT;

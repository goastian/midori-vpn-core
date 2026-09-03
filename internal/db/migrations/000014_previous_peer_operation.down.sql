-- 000014_previous_peer_operation.down.sql

BEGIN;

ALTER TABLE peer_operations
    DROP COLUMN previous_operation_id;

COMMIT;

-- 000014_previous_peer_operation.up.sql
-- Capture the exact Core owner of the peer replaced by a durable operation.

BEGIN;

ALTER TABLE peer_operations
    ADD COLUMN previous_operation_id UUID;

COMMIT;

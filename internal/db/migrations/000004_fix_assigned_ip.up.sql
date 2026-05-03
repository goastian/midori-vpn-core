-- Fix peers.assigned_ip rows that were stored with a duplicate /32 suffix
-- (e.g. "10.8.0.2/32/32" → "10.8.0.2/32") caused by a previous bug where
-- the CIDR mask was appended twice during peer creation.
BEGIN;
UPDATE peers
SET assigned_ip = regexp_replace(assigned_ip, '(/32)+$', '/32')
WHERE assigned_ip ~ '/32/32';
COMMIT;

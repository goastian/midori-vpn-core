BEGIN;

-- ── peers ────────────────────────────────────────────────────────────────────
-- Speed up public-key lookups (peer activation, WireGuard sync).
CREATE INDEX IF NOT EXISTS idx_peers_public_key
    ON peers (public_key);

-- Speed up queries that filter by is_active (e.g. list active peers per server).
CREATE INDEX IF NOT EXISTS idx_peers_is_active
    ON peers (is_active) WHERE is_active = TRUE;

-- Speed up assigned-IP existence checks (IP pool integrity validation).
CREATE INDEX IF NOT EXISTS idx_peers_assigned_ip
    ON peers (assigned_ip);

-- Speed up pagination ordered by creation time.
CREATE INDEX IF NOT EXISTS idx_peers_created_at
    ON peers (created_at DESC);

-- ── vpn_servers ──────────────────────────────────────────────────────────────
-- Speed up filtering active servers (server picker on connect).
CREATE INDEX IF NOT EXISTS idx_vpn_servers_is_active
    ON vpn_servers (is_active) WHERE is_active = TRUE;

-- ── audit_logs ───────────────────────────────────────────────────────────────
-- Speed up time-sorted audit log queries (admin dashboard, alerts).
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
    ON audit_logs (created_at DESC);

COMMIT;

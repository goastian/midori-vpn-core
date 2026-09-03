-- Support bounded recent-session reads for the per-user Dashboard summary.

BEGIN;

CREATE INDEX idx_peers_user_created
    ON peers (user_id, created_at DESC, id DESC);

COMMIT;

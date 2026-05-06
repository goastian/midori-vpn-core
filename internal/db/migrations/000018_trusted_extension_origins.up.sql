-- Browser extension origins trusted via TOFU (Trust On First Use).
-- The first time an authenticated user completes the OAuth callback from a
-- given moz-extension:// or chrome-extension:// origin, that origin is
-- registered here. Subsequent requests from the same origin are validated
-- against this table when ALLOWED_EXTENSION_ORIGINS is empty.
CREATE TABLE IF NOT EXISTS trusted_extension_origins (
    origin           TEXT PRIMARY KEY,
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    seen_count       BIGINT      NOT NULL DEFAULT 1,
    revoked          BOOLEAN     NOT NULL DEFAULT FALSE,
    CONSTRAINT trusted_extension_origins_scheme_chk
        CHECK (origin LIKE 'moz-extension://%' OR origin LIKE 'chrome-extension://%')
);

CREATE INDEX IF NOT EXISTS idx_trusted_extension_origins_active
    ON trusted_extension_origins (origin) WHERE revoked = FALSE;

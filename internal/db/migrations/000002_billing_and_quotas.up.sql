-- 000002_billing_and_quotas.up.sql
-- Midori VPN Billing, Quotas & Device Management Schema

BEGIN;

-- 1. Tabla de Caché Local de Suscripciones y Entitlements de astian-payment
CREATE TABLE IF NOT EXISTS user_subscriptions (
    user_id              UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    plan_id              BIGINT,
    plan_slug            TEXT        NOT NULL DEFAULT 'free',
    plan_name            TEXT        NOT NULL DEFAULT 'Free Plan',
    stripe_status        TEXT        NOT NULL DEFAULT 'active',
    is_active            BOOLEAN     NOT NULL DEFAULT TRUE,
    is_on_trial          BOOLEAN     NOT NULL DEFAULT FALSE,
    is_on_grace_period   BOOLEAN     NOT NULL DEFAULT FALSE,
    max_devices          INTEGER     NOT NULL DEFAULT 1,
    bandwidth_limit_gb   BIGINT      NOT NULL DEFAULT 10,   -- 0 = Ilimitado
    speed_limit_mbps     INTEGER     NOT NULL DEFAULT 0,    -- 0 = Ilimitado
    allowed_locations    TEXT[]      NOT NULL DEFAULT '{"DO","US"}',
    adblock_enabled      BOOLEAN     NOT NULL DEFAULT FALSE,
    trial_ends_at        TIMESTAMPTZ,
    current_period_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_period_end   TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 month',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_subscriptions_active ON user_subscriptions (is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_plan ON user_subscriptions (plan_slug);

-- 2. Tabla de Histórico y Control de Consumo de Ancho de Banda
CREATE TABLE IF NOT EXISTS user_bandwidth_usage (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    period_start        TIMESTAMPTZ NOT NULL,
    period_end          TIMESTAMPTZ NOT NULL,
    bytes_uploaded      BIGINT      NOT NULL DEFAULT 0,
    bytes_downloaded    BIGINT      NOT NULL DEFAULT 0,
    total_bytes         BIGINT      NOT NULL DEFAULT 0,
    is_throttled        BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_user_bandwidth_period UNIQUE (user_id, period_start)
);

CREATE INDEX IF NOT EXISTS idx_user_bandwidth_lookup ON user_bandwidth_usage (user_id, period_start, period_end);

-- 3. Columnas de estrangulamiento y control en tabla peers
ALTER TABLE peers ADD COLUMN IF NOT EXISTS is_throttled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE peers ADD COLUMN IF NOT EXISTS max_speed_kbps INTEGER NOT NULL DEFAULT 0;

COMMIT;

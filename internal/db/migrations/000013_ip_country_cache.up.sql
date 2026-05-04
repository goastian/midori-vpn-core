CREATE TABLE IF NOT EXISTS ip_country_cache (
    ip          TEXT        PRIMARY KEY,
    country_code CHAR(2)    NOT NULL,
    cached_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

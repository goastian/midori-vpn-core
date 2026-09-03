-- 000017_multicluster_model.up.sql
-- Durable cluster, Core node, desired revision and observation model.

BEGIN;

CREATE TABLE clusters (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT        NOT NULL,
    region          TEXT        NOT NULL,
    state           TEXT        NOT NULL DEFAULT 'inactive',
    policy_labels   JSONB       NOT NULL DEFAULT '{}'::JSONB,
    is_principal    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_clusters_name CHECK (length(name) BETWEEN 1 AND 64),
    CONSTRAINT chk_clusters_region CHECK (length(region) BETWEEN 1 AND 64),
    CONSTRAINT chk_clusters_state CHECK (
        state IN ('enrolling', 'inactive', 'active', 'draining', 'revoked', 'retired')
    ),
    CONSTRAINT chk_clusters_policy_labels CHECK (jsonb_typeof(policy_labels) = 'object'),
    CONSTRAINT chk_clusters_timestamps CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX uq_clusters_name_ci ON clusters (lower(name));
CREATE UNIQUE INDEX uq_clusters_principal ON clusters (is_principal) WHERE is_principal = TRUE;
CREATE INDEX idx_clusters_region_state ON clusters (region, state);

CREATE TABLE core_nodes (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id          UUID        NOT NULL REFERENCES clusters(id) ON DELETE RESTRICT,
    name                TEXT        NOT NULL,
    management_host     TEXT        NOT NULL,
    state               TEXT        NOT NULL DEFAULT 'enrolling',
    core_version        TEXT        NOT NULL DEFAULT '',
    last_seen_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_core_nodes_cluster_name UNIQUE (cluster_id, name),
    CONSTRAINT chk_core_nodes_name CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    CONSTRAINT chk_core_nodes_management_host CHECK (
        length(management_host) BETWEEN 1 AND 253
        AND management_host !~ '[[:space:]/?#@]'
    ),
    CONSTRAINT chk_core_nodes_state CHECK (
        state IN ('enrolling', 'inactive', 'active', 'draining', 'revoked', 'retired')
    ),
    CONSTRAINT chk_core_nodes_version CHECK (length(core_version) <= 64),
    CONSTRAINT chk_core_nodes_seen_order CHECK (last_seen_at IS NULL OR last_seen_at >= created_at),
    CONSTRAINT chk_core_nodes_timestamps CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX uq_core_nodes_management_host_ci ON core_nodes (lower(management_host));
CREATE INDEX idx_core_nodes_cluster_state ON core_nodes (cluster_id, state);
CREATE INDEX idx_core_nodes_last_seen ON core_nodes (last_seen_at DESC) WHERE last_seen_at IS NOT NULL;

CREATE TABLE node_enrollment_tokens (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         UUID        NOT NULL REFERENCES core_nodes(id) ON DELETE RESTRICT,
    token_hash      BYTEA       NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_node_enrollment_tokens_hash UNIQUE (token_hash),
    CONSTRAINT chk_node_enrollment_tokens_hash CHECK (octet_length(token_hash) = 32),
    CONSTRAINT chk_node_enrollment_tokens_expiry CHECK (expires_at > created_at),
    CONSTRAINT chk_node_enrollment_tokens_terminal CHECK (
        NOT (used_at IS NOT NULL AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT chk_node_enrollment_tokens_used_order CHECK (used_at IS NULL OR used_at >= created_at),
    CONSTRAINT chk_node_enrollment_tokens_revoked_order CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE UNIQUE INDEX uq_node_enrollment_tokens_live_node
    ON node_enrollment_tokens (node_id)
    WHERE used_at IS NULL AND revoked_at IS NULL;
CREATE INDEX idx_node_enrollment_tokens_expiry
    ON node_enrollment_tokens (expires_at)
    WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE TABLE desired_revisions (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id                 UUID        NOT NULL REFERENCES core_nodes(id) ON DELETE RESTRICT,
    revision                BIGINT      NOT NULL,
    previous_revision       BIGINT,
    schema_version          INTEGER     NOT NULL,
    minimum_core_version    TEXT        NOT NULL,
    payload                 JSONB       NOT NULL,
    payload_sha256          BYTEA       NOT NULL,
    signature               BYTEA       NOT NULL,
    signing_key_id          TEXT        NOT NULL,
    issued_at               TIMESTAMPTZ NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_desired_revisions_node_revision UNIQUE (node_id, revision),
    CONSTRAINT fk_desired_revisions_previous
        FOREIGN KEY (node_id, previous_revision)
        REFERENCES desired_revisions(node_id, revision) ON DELETE RESTRICT,
    CONSTRAINT chk_desired_revisions_revision CHECK (revision >= 1),
    CONSTRAINT chk_desired_revisions_previous CHECK (
        (revision = 1 AND previous_revision IS NULL)
        OR (revision > 1 AND previous_revision IS NOT NULL AND previous_revision < revision)
    ),
    CONSTRAINT chk_desired_revisions_schema CHECK (schema_version >= 1),
    CONSTRAINT chk_desired_revisions_minimum_version CHECK (length(minimum_core_version) BETWEEN 1 AND 64),
    CONSTRAINT chk_desired_revisions_payload CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT chk_desired_revisions_digest CHECK (octet_length(payload_sha256) = 32),
    CONSTRAINT chk_desired_revisions_signature CHECK (octet_length(signature) = 64),
    CONSTRAINT chk_desired_revisions_signing_key CHECK (length(signing_key_id) BETWEEN 1 AND 128),
    CONSTRAINT chk_desired_revisions_expiry CHECK (expires_at > issued_at)
);

CREATE INDEX idx_desired_revisions_node_latest ON desired_revisions (node_id, revision DESC);
CREATE INDEX idx_desired_revisions_expiry ON desired_revisions (expires_at);

CREATE TABLE node_observations (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id             UUID        NOT NULL REFERENCES core_nodes(id) ON DELETE RESTRICT,
    applied_revision    BIGINT,
    core_version        TEXT        NOT NULL,
    health_status       TEXT        NOT NULL,
    version_compatible  BOOLEAN     NOT NULL DEFAULT FALSE,
    current_peers       INTEGER     NOT NULL DEFAULT 0,
    max_peers           INTEGER     NOT NULL DEFAULT 0,
    transport_states    JSONB       NOT NULL DEFAULT '{}'::JSONB,
    last_error_code     TEXT        NOT NULL DEFAULT '',
    reported_at         TIMESTAMPTZ NOT NULL,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_node_observations_revision
        FOREIGN KEY (node_id, applied_revision)
        REFERENCES desired_revisions(node_id, revision) ON DELETE RESTRICT,
    CONSTRAINT chk_node_observations_version CHECK (length(core_version) BETWEEN 1 AND 64),
    CONSTRAINT chk_node_observations_health CHECK (
        health_status IN ('unknown', 'healthy', 'degraded', 'error')
    ),
    CONSTRAINT chk_node_observations_capacity CHECK (
        current_peers >= 0 AND max_peers >= 0 AND current_peers <= max_peers
    ),
    CONSTRAINT chk_node_observations_transports CHECK (jsonb_typeof(transport_states) = 'object'),
    CONSTRAINT chk_node_observations_error_code CHECK (
        last_error_code = '' OR last_error_code ~ '^[a-z0-9_]{1,64}$'
    )
);

CREATE INDEX idx_node_observations_node_latest
    ON node_observations (node_id, received_at DESC, id DESC);
CREATE INDEX idx_node_observations_health ON node_observations (health_status, received_at DESC);

ALTER TABLE vpn_servers
    ADD COLUMN node_id UUID REFERENCES core_nodes(id) ON DELETE RESTRICT,
    ADD COLUMN legacy_node_unbound BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT chk_vpn_servers_node_binding CHECK (
        NOT (node_id IS NOT NULL AND legacy_node_unbound = TRUE)
    );

-- Existing server rows stay available during the controlled migration, but
-- are explicitly identifiable and cannot be represented as enrolled nodes.
UPDATE vpn_servers SET legacy_node_unbound = TRUE WHERE node_id IS NULL;

CREATE UNIQUE INDEX uq_vpn_servers_node ON vpn_servers (node_id) WHERE node_id IS NOT NULL;
CREATE INDEX idx_vpn_servers_legacy_unbound
    ON vpn_servers (legacy_node_unbound) WHERE legacy_node_unbound = TRUE;

CREATE FUNCTION vpn_server_placement_eligible(
    requested_server_id UUID,
    requested_protocol TEXT,
    freshness INTERVAL DEFAULT INTERVAL '90 seconds',
    capacity_required BOOLEAN DEFAULT TRUE
) RETURNS BOOLEAN
LANGUAGE SQL
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
    SELECT COALESCE((
        SELECT
            server.is_active
            AND (NOT capacity_required OR server.current_peers < server.max_peers)
            AND (
                server.legacy_node_unbound
                OR (
                    server.node_id IS NOT NULL
                    AND cluster.state = 'active'
                    AND node.state = 'active'
                    AND node.core_version <> ''
                    AND node.last_seen_at >= CURRENT_TIMESTAMP - freshness
                    AND desired.revision IS NOT NULL
                    AND desired.expires_at > CURRENT_TIMESTAMP
                    AND observation.id IS NOT NULL
                    AND observation.received_at >= CURRENT_TIMESTAMP - freshness
                    AND observation.health_status = 'healthy'
                    AND observation.version_compatible = TRUE
                    AND observation.core_version = node.core_version
                    AND observation.applied_revision = desired.revision
                    AND (NOT capacity_required OR observation.current_peers < observation.max_peers)
                    AND EXISTS (
                        SELECT 1
                        FROM vpn_server_transports transport
                        WHERE transport.server_id = server.id
                          AND (requested_protocol IS NULL OR transport.protocol = requested_protocol)
                          AND transport.enabled = TRUE
                          AND transport.health_status = 'healthy'
                          AND transport.last_checked_at >= CURRENT_TIMESTAMP - freshness
                          AND observation.transport_states @> jsonb_build_object(
                              transport.protocol,
                              jsonb_build_object('status', 'healthy', 'certified', TRUE)
                          )
                    )
                )
            )
        FROM vpn_servers server
        LEFT JOIN core_nodes node ON node.id = server.node_id
        LEFT JOIN clusters cluster ON cluster.id = node.cluster_id
        LEFT JOIN LATERAL (
            SELECT revision, expires_at
            FROM desired_revisions
            WHERE node_id = node.id
            ORDER BY revision DESC
            LIMIT 1
        ) desired ON TRUE
        LEFT JOIN LATERAL (
            SELECT id, applied_revision, core_version, health_status,
                   version_compatible, current_peers, max_peers,
                   transport_states, received_at
            FROM node_observations
            WHERE node_id = node.id
            ORDER BY received_at DESC, id DESC
            LIMIT 1
        ) observation ON TRUE
        WHERE server.id = requested_server_id
          AND freshness > INTERVAL '0 seconds'
    ), FALSE)
$$;

COMMENT ON FUNCTION vpn_server_placement_eligible(UUID, TEXT, INTERVAL, BOOLEAN) IS
    'Fail-closed placement gate for modeled nodes; legacy_node_unbound is a temporary rollout exception';

COMMIT;

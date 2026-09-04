-- Keep transport certification under central administrative control. Signed
-- node observations prove node health/revision/capacity, but cannot certify
-- their own transports.

BEGIN;

CREATE OR REPLACE FUNCTION vpn_server_placement_eligible(
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
                          AND desired.payload @> jsonb_build_object(
                              'transports', jsonb_build_array(jsonb_build_object(
                                  'protocol', transport.protocol,
                                  'enabled', TRUE
                              ))
                          )
                          AND (
                              transport.protocol NOT IN ('openvpn', 'ikev2')
                              OR transport.metadata @> '{"certified": true}'::JSONB
                          )
                    )
                )
            )
        FROM vpn_servers server
        LEFT JOIN core_nodes node ON node.id = server.node_id
        LEFT JOIN clusters cluster ON cluster.id = node.cluster_id
        LEFT JOIN LATERAL (
            SELECT revision, expires_at, payload
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
    'Fail-closed placement using signed node health and centrally certified transport state; legacy_node_unbound is a temporary rollout exception';

COMMIT;

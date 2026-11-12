-- Operator-only bootstrap, not a migration or a new placement authority.
-- scripts/activate-core.sh supplies the session settings below. Keep this file
-- plain SQL so PostgreSQL integration tests execute the same transaction.
BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;
SET LOCAL search_path = pg_catalog, public;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15s';

DO $activation$
DECLARE
    requested_cluster UUID := current_setting('midorivpn.activation.cluster_id')::UUID;
    requested_node UUID := current_setting('midorivpn.activation.node_id')::UUID;
    requested_server UUID := current_setting('midorivpn.activation.server_id')::UUID;
    requested_protocol TEXT := current_setting('midorivpn.activation.protocol');
    cluster public.clusters%ROWTYPE;
    node public.core_nodes%ROWTYPE;
    server public.vpn_servers%ROWTYPE;
    observation public.node_observations%ROWTYPE;
BEGIN
    -- Runtime has DML but deliberately has neither schema CREATE nor owner
    -- membership. Do not allow this operator tool to run under runtime identity.
    IF session_user <> current_setting('midorivpn.activation.migrator_role')
       OR NOT has_schema_privilege(session_user, 'public', 'CREATE') THEN
        RAISE EXCEPTION 'activation requires the configured migrator identity'
            USING ERRCODE = '42501';
    END IF;
    IF requested_protocol NOT IN ('wireguard', 'masque', 'wss', 'proxy', 'openvpn', 'ikev2') THEN
        RAISE EXCEPTION 'activation requires an explicit supported protocol';
    END IF;

    -- These locks also serialize against enrollment, revocation, desired-state
    -- issuance and heartbeat (MulticlusterRepo), and server/transport updates.
    SELECT * INTO cluster FROM public.clusters WHERE id = requested_cluster FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'activation cluster not found';
    END IF;
    SELECT * INTO node FROM public.core_nodes WHERE id = requested_node FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'activation node not found';
    END IF;
    SELECT * INTO server FROM public.vpn_servers WHERE id = requested_server FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'activation server not found';
    END IF;
    IF node.cluster_id <> cluster.id THEN
        RAISE EXCEPTION 'activation node belongs to a different cluster';
    END IF;
    IF cluster.state NOT IN ('enrolling', 'inactive', 'active')
       OR node.state NOT IN ('inactive', 'active') THEN
        RAISE EXCEPTION 'activation refuses draining, revoked, retired or unenrolled lifecycle state';
    END IF;
    IF node.identity_public_key IS NULL OR octet_length(node.identity_public_key) <> 32
       OR node.enrolled_at IS NULL THEN
        RAISE EXCEPTION 'activation requires an enrolled node identity';
    END IF;
    IF NOT server.is_active OR server.draining_at IS NOT NULL THEN
        RAISE EXCEPTION 'activation refuses an inactive or draining server';
    END IF;
    IF server.max_peers < 1 OR server.current_peers < 0 OR server.current_peers > server.max_peers THEN
        RAISE EXCEPTION 'activation refuses inconsistent server capacity';
    END IF;
    IF server.legacy_node_unbound THEN
        RAISE EXCEPTION 'activation refuses legacy placement exceptions';
    END IF;
    IF server.node_id IS NOT NULL AND server.node_id <> node.id THEN
        RAISE EXCEPTION 'activation refuses to reassign a server to another node';
    END IF;
    IF EXISTS (SELECT 1 FROM public.vpn_servers WHERE node_id = node.id AND id <> server.id) THEN
        RAISE EXCEPTION 'activation node is already bound to another server';
    END IF;
    IF cluster.state <> 'active' AND EXISTS (
        SELECT 1 FROM public.core_nodes WHERE cluster_id = cluster.id AND id <> node.id AND state = 'active'
    ) THEN
        RAISE EXCEPTION 'activation would also enable another active node in this cluster';
    END IF;

    SELECT * INTO observation FROM public.node_observations
    WHERE node_id = node.id ORDER BY received_at DESC, id DESC LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'activation requires a node observation';
    END IF;
    IF node.last_seen_at IS DISTINCT FROM observation.received_at
       OR node.enrolled_at > observation.received_at
       OR observation.received_at > clock_timestamp()
       OR observation.last_error_code <> '' THEN
        RAISE EXCEPTION 'activation refuses inconsistent or failed observed state';
    END IF;
    IF server.node_id IS NULL AND (
        server.current_peers <> 0 OR observation.current_peers <> 0
        OR EXISTS (SELECT 1 FROM public.peers WHERE server_id = server.id AND is_active)
        OR EXISTS (
            SELECT 1 FROM public.peer_operations operation
            LEFT JOIN public.peers previous ON previous.id = operation.previous_peer_id
            WHERE operation.state IN ('pending', 'core_applied', 'cleanup_pending')
              AND (operation.server_id = server.id OR previous.server_id = server.id)
        )
        OR EXISTS (
            SELECT 1 FROM public.device_certificates
            WHERE server_id = server.id AND revoked_at IS NULL AND not_after > clock_timestamp()
        )
    ) THEN
        RAISE EXCEPTION 'activation refuses an initial binding with existing sessions, credentials or operations';
    END IF;

    -- Preserve updated_at on retries: a successful repeat is a real no-op.
    UPDATE public.clusters SET state = 'active', updated_at = clock_timestamp()
    WHERE id = cluster.id AND state <> 'active';
    UPDATE public.core_nodes SET state = 'active', updated_at = clock_timestamp()
    WHERE id = node.id AND state <> 'active';
    UPDATE public.vpn_servers SET node_id = node.id, legacy_node_unbound = FALSE, updated_at = clock_timestamp()
    WHERE id = server.id AND node_id IS NULL;

    -- Never bypass the existing central authority: fresh healthy observation,
    -- matching latest applied revision, live desired lease, capacity, and a
    -- fresh enabled transport permitted by desired intent/central certification.
    -- Failure here rolls back ALL three writes, including the legacy flag.
    IF NOT public.vpn_server_placement_eligible(server.id, requested_protocol, INTERVAL '90 seconds', TRUE) THEN
        RAISE EXCEPTION 'activation placement gate failed: check heartbeat, health, version, desired revision/lease, capacity and central transport inventory';
    END IF;
END
$activation$;

COMMIT;

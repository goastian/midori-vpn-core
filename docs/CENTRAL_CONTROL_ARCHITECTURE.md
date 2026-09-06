# Central Control and regional Core architecture

Status: target architecture for MidoriVPN 2.0.0 and later regional rollout.

This document defines how one logical Control plane manages the Core node on
the principal server and additional independent regional Core clusters. It is
the architecture contract, not evidence that a second server has completed the
acceptance gate. The current implementation and the remaining rollout gates
are identified separately throughout the document.

## Objectives

- Keep user identity, policy, billing, server inventory and desired state in
  one central Control plane.
- Run the principal Control together with one local Core exit node.
- Add regional Core capacity without copying the Control database, Authentik
  credentials, private client CA or Control private signing key.
- Isolate a regional failure or compromise from every other regional cluster.
- Preserve established tunnels when Control or its database is temporarily
  unavailable.
- Advertise only transports that are enabled, healthy and certified.

High availability for Control/PostgreSQL and active-active WireGuard state
inside a region are not part of this contract. A cluster is initially an
operational and failure boundary; it is not a consensus group.

## Topology

```text
                              public HTTPS
 Users and administrators ----------------------+
                                                  v
                     +-------------------------------------------+
                     | Principal                                 |
                     |                                           |
                     | Nginx -> Control/Core API -> PostgreSQL   |
                     |                    |       -> Redis        |
                     |                    +-> local Core node     |
                     |                    +-> Prometheus/Grafana  |
                     +--------------------+----------------------+
                                          |
                         private management network, TLS,
                         signed Control requests
                    +---------------------+---------------------+
                    |                                           |
                    v                                           v
          +--------------------+                     +--------------------+
          | Regional cluster A |                     | Regional cluster B |
          | Core node          |                     | Core node          |
          | local replay Redis |                     | local replay Redis |
          | local gateways     |                     | local gateways     |
          +--------------------+                     +--------------------+
             ^ public data plane                        ^ public data plane
             +---------------- clients -----------------+
```

The principal is also a cluster and its local Core is managed through the same
signed Core API used for regional nodes. This avoids a privileged local-only
management path.

For the first regional rollout, one `vpn_servers` row maps to one Core node and
each regional cluster contains one node. More nodes may be placed in the same
region as separate servers, but they do not share live tunnel state. The
`cluster_id` groups those nodes for policy, rollout and observability; it does
not make an existing tunnel portable between them.

## Component ownership

| Capability or data | Principal | Regional Core cluster |
|---|---|---|
| Control API and SPA | Yes | Never |
| PostgreSQL / PgBouncer | Yes | Never |
| Authentik client configuration | Yes | Never |
| Client CA private signing key | Yes | Never |
| Control Ed25519 private key | Yes | Never |
| Control Ed25519 public trust key | Yes | Yes |
| Core process and WireGuard state | Local node | Local node |
| Replay-protection Redis | Yes | One private local instance per node |
| Public client CA and CRL | As required | As required by gateways |
| OpenVPN/IKEv2 gateway certificates | Local gateway only | Local gateway only |
| Private observability target | Yes | Yes, reachable only from principal |

Regional nodes receive public trust material and node-local gateway secrets
only. Environment files, images, logs, support bundles and metrics must never
contain Control database credentials, Authentik secrets, the private client CA
or the Control private key.

## Client placement and failover contract

Clients discover a protocol-specific placement through
`GET /api/v1/control/servers/candidates?protocol=...`. The response is
fail-closed: it excludes legacy-unbound and draining servers, exhausted
capacity, stale desired/observed state, and transports that are not healthy and
centrally certified. A server without an explicitly configured HTTPS
`probe_url` is also excluded; migration does not guess a public address for
historical rows.

Every candidate points to the fixed public path
`/.well-known/midorivpn/edge-health`. Core serves `GET` and `HEAD` with `204`,
`Cache-Control: no-store`, no response body or operational metadata, and a
per-source rate limit that remains active even when the general development
limiter is disabled. Clients measure this endpoint themselves. The former user
ping was removed because it measured Control-to-Core reachability and could not
represent client latency.

Administrators retain the distinct
`GET /api/v1/admin/servers/reachability` diagnostic. Its value is named
`control_latency_ms` to make the measurement origin explicit. Connection
operations persist `connection_reason=user|automatic_failover`; this audit
attribute never changes or replaces the persistent device identity.

The candidate contract only governs new placement and reconnection. An
established tunnel remains local to its current Core, and loss of the principal
prevents new candidate discovery without terminating already established data
plane traffic.

## Planes and request flow

### User and administration plane

All OAuth, user and administrator traffic terminates at the principal Control
endpoint. A client never authenticates against a regional Core. Control is the
only service that reads or writes users, peers, quotas, server inventory and
transport declarations in PostgreSQL.

### Core management plane

Control contacts the selected Core through its private management hostname.
Every mutating or sensitive Core request is covered by the existing Ed25519
request signature: caller ID, method, request target, body digest, timestamp
and a random nonce. Core checks the signature, a 30-second clock window,
revocation state and a single-use nonce. Production replay state is held in the
node-local authenticated Redis.

Management ingress must use TLS with certificate verification and an allowlist
that admits only the principal management network. `CORE_TLS_SKIP_VERIFY` and
plain HTTP are prohibited in production. The Core management HTTP port is not
Internet-facing. `/metrics` is absent from that router and exists only on the
dedicated TLS 1.3/mTLS observability listener on TCP/9443.

The current signed operations add, update, remove and inspect WireGuard peers
and return node statistics. Retries and a per-host circuit breaker already
exist in Control. These calls are the implemented management baseline.

Every add request carries a non-zero `operation_id` UUID. Core durably binds
that operation to the canonical 32-byte WireGuard public key before applying
the peer to the kernel. Replaying the same operation and key returns the same
address without another allocation; using either the key or operation for a
different owner returns `peer_operation_conflict`. Removal requires
`expected_operation_id`, so a delayed compensation cannot remove a peer that a
later operation replaced. An already absent peer is a successful idempotent
removal. The node stores this ownership map atomically beside its WireGuard
configuration and assigns a stable legacy operation once to peers restored
from pre-contract state.

Peer enumeration is fail-closed. If Core cannot observe the WireGuard device,
it returns `503 core_peer_state_unavailable`; it never converts that failure
into an empty list. Configurable IPv4 pools are limited to `/16` through `/30`,
and the interface gateway retains the configured prefix. Control currently
persists every connect or replacement in `peer_operations` before contacting
Core. The row owns the exact operation UUID, device, key, target server,
reserved capacity, prior peer, assigned address, retry count and transition
timestamps. The exact prior Core operation is captured before replacement,
including for adopted legacy peers. `peers.provision_operation_id` preserves
the operation that owns each completed session. A pending retry returns
`409 connection_in_progress` with `Retry-After`; a completed retry returns the
same session and sensitive configuration rather than allocating again. Control
applies the rate limit only to genuinely new provisioning. Once Core has
accepted a peer, the `core_applied` and completion writes use a separate
strictly bounded context so an HTTP disconnect cannot abandon the durable
transition. Desktop retries an ambiguous transport/5xx result and
`connection_in_progress` with the same WireGuard public key; definitive 4xx
responses remain terminal. Thus a lost response is resolved through the same
operation/session instead of allocating another peer. Control reconciles
immediately at startup and every 60 seconds. Operations become
eligible for recovery after two minutes, while fresh operations remain
protected from an older Core snapshot.

### Data plane

Clients connect directly to the selected node's certified transport endpoint.
Regional client traffic does not traverse the principal. Each cluster owns its
WireGuard interface, address pool, public endpoints and rootful gateways.

WireGuard, WSS, MASQUE, PostgreSQL, Redis and the application remain rootless
where their kernel requirements allow it. OpenVPN/DCO and strongSwan/XFRM use
minimal rootful Quadlets with host networking. A hardened host service remains
only a documented rollback fallback when rootful containment cannot operate.

## Sources of truth and consistency

The central database is authoritative for users, registered devices, policy,
server inventory, transport declarations and intended peer placement. A Core
node is authoritative for observed local tunnel state and counters. Neither
regional Redis nor a gateway health file becomes a second Control database.

Device identity and session identity are distinct. `devices` records one
installation by `(user_id, client_instance_id)` and stores its reported name,
optional user alias, explicit client type and optional private adapter HMAC
reference. `peers` remains session history and references the device that
created each current session. Quota counts distinct devices with an active
session, never historical peer rows or certificates. The adapter reference is
indexed only for diagnostics and must never be treated as unique.

During the 2.0 migration, each active peer without a persistent installation
ID receives its own legacy device; inactive peers remain history without
creating visible devices. A registered client may adopt one active legacy
record only when user and reported name produce exactly one candidate. Equal
or otherwise ambiguous names remain separate for explicit cleanup. A raw MAC
address is neither accepted by the contract nor persisted in PostgreSQL.

The user-facing API lists stable devices separately from sessions. A device
response embeds at most its current active session; prior sessions are retained
under a paginated device-history endpoint, while the compatibility connection
list returns active sessions only. Revoking a device first requires its Core
peer removal to converge, then atomically deactivates the database session,
invalidates recoverable peer material, revokes its client certificates and
marks the device revoked without deleting audit history. Until durable cleanup
converges, the API returns an explicit pending state and retains the operation
for reconciliation instead of reporting success or discarding intent.

JWT/JWE validation resolves an existing Authentik subject with a read-only
MVCC lookup when its email and group claims are unchanged. Only a real claim
change performs the conditional JIT upsert. This keeps ordinary authenticated
requests, including Disconnect, independent of row locks held briefly by peer
lifecycle transactions while preserving fail-closed synchronization for new
or changed identities.

A successful connection or replacement follows this order:

1. Control authenticates the user, locks the user, device and key, then
   revalidates quota and target capacity inside one database transaction.
2. Control writes a pending operation and reserves target capacity atomically.
3. Control signs an idempotent add-peer request using that operation UUID.
4. Core applies or recognizes the operation and returns its stable address.
5. Control records `core_applied`, creates the new peer, retires the previous
   database session and adjusts cross-server counters in one transaction. A
   replacement remains `cleanup_pending`; a first connection is `completed`.
6. Control removes the exact previous Core operation and only then marks the
   replacement `completed`. A crash or failure preserves `cleanup_pending`
   without losing either operation owner.

Only a definitive Core rejection releases a pending reservation immediately;
ambiguous transport or persistence failures retain durable state for the
reconciler. Reconciliation compares central active peers only with a
successfully observed signed Core peer list; an error never becomes an empty
list. It completes already-applied operations, retries idempotent adds, retires
database sessions absent from a valid observation and removes Core orphans by
their exact `(public_key, operation_id)`. Peer state and the logical server
counter are repaired in the same PostgreSQL transaction. Retrying a completed
operation cannot allocate another address or count the same peer twice.

Desktop records the exact peer ID in a private atomic per-user cleanup queue
before it tears down a local transport. Backend failures retain that entry for
bounded retry and process restart; a successful or accepted idempotent DELETE
removes it. If neither durable local recording nor immediate backend retirement
is possible, the client keeps the active connection identity and reports an
error so a later request can retry safely.

There is no cross-cluster replication of WireGuard runtime state. Moving a
device to another server creates a new placement and removes the old one after
the new placement succeeds.

## Signed desired configuration

The implemented API signs each Control request and distributes a versioned,
deterministic desired-configuration bundle containing at least:

- `schema_version`, `cluster_id`, `node_id` and a monotonically increasing
  `revision`;
- issue and expiry times plus the minimum compatible Core version;
- declared public and management endpoints;
- enabled transport definitions, priority, capacity and certification state;
- references to node-local secret names or certificate fingerprints, never the
  secret values themselves; and
- the previous accepted revision for an auditable transition.

The Ed25519 signature uses a domain distinct from request signing. A node
accepts only its own identity, a supported schema, a newer revision and an
unexpired bundle signed by a trusted Control key. It validates all referenced
local material before atomically activating the revision. If activation fails,
the last-known-good revision stays active and the rejection is reported as
observed state.

For 2.0, the same Control Ed25519 identity may sign requests and bundles with
strict domain separation. Core stores only its public key. Rotation installs a
second trusted public key, verifies a bundle with it and only then retires the
old key. Private-key storage in an HSM or external signer is a later hardening
option, not a deployment dependency.

## Enrollment, identity and revocation

Initial regional enrollment is an operator-controlled process:

1. Create an inactive cluster and an `enrolling` node in Control.
2. Issue a one-use enrollment token with a lifetime between one minute and 24
   hours and place that plaintext token in the node's private state directory.
3. Provision the Control public key and private management-network trust.
4. Issue the management TLS certificate for the exact node hostname.
5. Add the hostname to the principal `CORE_ALLOWED_HOSTS` allowlist.
6. Start Core with the exact Control origin, node UUID, private state directory
   and capacity. Core generates its Ed25519 identity locally and enrolls itself.
7. Confirm that the token file is gone and signed heartbeats are persisted.
8. Register the server and explicit transport rows as inactive.
9. Verify signed peer operations, replay rejection, statistics and cleanup.
10. Mark only certified transports healthy, then activate the server.

The existing admin identity registry updates the Redis attached to the
principal process. Regional nodes use independent Redis instances, so it is not
yet a fleet-wide revocation channel. Control-key rotation or emergency
revocation on regional nodes is a coordinated configuration deployment
followed by verification on every node. No document or UI may claim
instantaneous fleet revocation before a
signed trust-revision contract is implemented and certified.

Node-originated enrollment and heartbeat use a separate node-specific Ed25519
identity. Core generates and atomically persists the private key in a `0700`
state directory with a `0600` identity file; Control stores only its 32-byte
public key. Enrollment requires both possession of a bounded, one-use token and
a valid self-signature by the proposed identity. Control stores only the
token's SHA-256 digest and marks the token used in the same PostgreSQL
transaction that binds the key. Core overwrites, truncates and removes its
local plaintext token only after Control confirms success.

Every later node-to-Control request signs a domain-separated canonical message
containing the node UUID, method, request target, body digest, timestamp and a
random nonce. Nonces are consumed through the principal Redis and fail closed
when replay protection is unavailable. Revoking a node immediately blocks
node-originated requests in PostgreSQL and revokes any unused enrollment token.
The reverse Control-to-Core direction retains its distinct signing domain and
node-local replay store.

## Credential boundary for WSS, MASQUE and proxy

Control issues canonical, compact `mvpn2` credentials signed with Ed25519 under
a transport-specific cryptographic domain. Claims bind `kid`, issuer,
audience, user, persistent device, server, cluster, issue/expiry timestamps and
a random `jti`. WSS, MASQUE and proxy verify the signature plus their exact
local audience, server and cluster before accepting traffic.

The Control private key remains on the principal. Regional nodes receive only
the dedicated `TRANSPORT_TOKEN_AUTHORIZED_KEYS` public trust store; it is kept
separate from general node-call authorization so another trusted node identity
cannot mint transport credentials. The former HMAC format is rejected by
default and is available only in `APP_ENV=development` with explicit
`ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS=true` and a separate legacy secret.

## Desired and observed node state

Control needs separate desired and observed records. The minimum target model
is:

| Record | Required fields |
|---|---|
| Cluster | ID, name, region, lifecycle state, policy labels |
| Node | ID, cluster ID, management hostname, Core version, last seen, trust state |
| Desired revision | Node ID, revision, schema, payload digest, signature, issued/expiry time |
| Observed revision | Node ID, applied revision, health, capacity, transport states, reported time |

Lifecycle states are `enrolling`, `inactive`, `active`, `draining`, `revoked`
and `retired`. A node is eligible for a new placement only when it is active,
its observed revision matches the desired revision, its report is fresh and at
least one requested transport is healthy and certified.

Migration 17 adds the durable `clusters`, `core_nodes`,
`node_enrollment_tokens`, `desired_revisions` and `node_observations` records,
plus the one-to-one `vpn_servers.node_id` binding. Enrollment tokens are stored
only by a 32-byte hash. The normal observation write path preserves history and
updates the node's bounded last-seen/version summary transactionally.

Placement now fails closed for a modeled node unless the cluster and node are
active, heartbeat and transport checks are fresh, the latest desired and
observed revisions match, Core reports a compatible version and the requested
transport is healthy and certified. Existing server rows were explicitly
marked `legacy_node_unbound` during the migration so the principal can remain
available while enrollment is implemented. Newly created unbound servers do
not receive placements, and the temporary historical exception must be removed
before regional certification.

Migration 18 binds an exact Ed25519 public key and enrollment timestamp to each
node, with a database uniqueness constraint preventing one identity from being
assigned to two nodes. Signed enrollment, heartbeat ingestion and desired-state
queries are implemented. Control creates a strict canonical bundle, signs it
with Ed25519 under the distinct `midorivpn-desired-state-v1` domain and persists
an exact locked revision chain. The target node polls at a jittered 30-second
interval, verifies target, time, version, signature and monotonic chain, then
atomically replaces its private `0600` last-known-good file while applying the
peer admission limit under the same local mutation lock. Invalid or stale
revisions leave the last-known-good untouched, and an expired local copy may be
restored after restart only to preserve established tunnels.

Control treats desired-state validity as a renewable lease. On startup and
every five minutes, the principal selects only the latest revision of each
active or draining enrolled node when less than six hours remain. It verifies
the stored canonical payload and its original signature before creating a new
24-hour revision with the same intent, a fresh issue/expiry window and an exact
previous-revision link. Creation uses the normal per-node transaction lock, so
an administrator update racing the renewer wins or produces a harmless
revision conflict. Expired leases are recoverable by the same verified path;
rows are never extended or overwritten. An invalid stored signature remains
closed and increments the renewal error metric.

Heartbeats report the applied revision and compatibility decision. Transport
certification is deliberately absent from desired intent and remains false in
observed state until the independent regional E2E gate records it.
WSS, MASQUE and proxy can be enabled by desired state only when already enabled
locally. OpenVPN and IKEv2 desired activation remain unavailable until their
regional local-capability boundary is implemented and certified.
Admin ping remains an on-demand probe and is not treated as a heartbeat.

## Observability

The principal Prometheus instance is the aggregation point. Every Core exposes
a dedicated TLS 1.3 listener on TCP/9443 that requires a client certificate
from its observability CA and the exact configured Prometheus SPIFFE URI SAN.
The public Core router and OpenAPI expose neither `/metrics` nor discovery.
Regional binds must be exact private IPv4 addresses reachable only from the
principal management network.

The principal supplies bounded HTTP service discovery from its central node
inventory. Only nodes in operational clusters and active/draining lifecycle
states are returned; stale operational nodes deliberately remain targets so
scrape failure and heartbeat-age alerts fire. Enrolling, inactive, revoked and
retired inventory is excluded. Labels are bounded to cluster, node and role;
user IDs, peer keys, client IPs and destination addresses are prohibited.

Control exposes aggregate reconciliation divergence, pending cleanup and live
peer-operation gauges alongside provisioning failures. Fleet series cover last
heartbeat, desired/observed revision convergence, version compatibility,
desired-signature rejection, lease expiry, automatic renewal outcomes,
capacity and bounded authentication/replay failure reasons. Alerting covers all
of those plus scrape availability and pending operations. Each node exposes
local HTTP, WireGuard capacity and transport health. Grafana remains
loopback-only and administrator access uses an SSH tunnel or an equivalent
private channel.

## Failure behavior

| Failure | Required behavior |
|---|---|
| Control, PostgreSQL or Authentik unavailable | Established data-plane tunnels remain active; new login, placement and policy changes fail closed. |
| Principal Redis unavailable | Control operations that need shared state fail readiness; existing regional tunnels continue. |
| Regional replay Redis unavailable | New signed management requests fail closed; existing local tunnels continue. |
| Regional node unreachable | Stop new placement on that node, open its circuit breaker, retain central intent and alert. Other clusters continue. |
| Transport gateway unhealthy | Stop advertising only that transport; do not deactivate unrelated healthy transports. |
| Desired bundle invalid or stale | Reject it and keep the last-known-good revision. |
| Control signing key suspected | Revoke/replace trust out of band on every node, stop new placement and rotate before restoration. |
| Abrupt node shutdown | On restart restore only durable intended peers, reconcile with Control and remove orphaned routes, interfaces, XFRM and nftables state. |

Regional nodes do not elect a replacement Control and never accept management
from another regional node. This prevents split-brain authority. If Control is
unreachable, a node may continue its last-known-good data plane but cannot
invent new policy or promote itself.

## Upgrade and rollback

1. Back up the central database and the affected node's local configuration.
2. Validate schema and API compatibility before changing desired state.
3. Drain one non-principal node and deploy the pinned image by digest.
4. Verify signed management, reported version/revision and every advertised
   transport.
5. Restore placement and observe it before advancing to another cluster.
6. Upgrade the principal Core last; upgrade Control only within the documented
   Core compatibility window.

Rollback restores the previous image digest and last-known-good desired
revision. Database migrations remain forward-only during a rolling node
upgrade; a migration requiring destructive rollback blocks the rollout.

## Current implementation matrix

| Contract | State |
|---|---|
| Principal Control plus local Core | Implemented and used in staging |
| Regional rootless Core plus private replay Redis | Deployment script implemented; second server not certified |
| Signed Control-to-Core requests and replay rejection | Implemented |
| TLS host allowlist and production fail-closed checks | Implemented |
| Central server/transport inventory and capacity reservation | Implemented |
| Per-host retries and circuit breaker | Implemented in memory |
| Persistent cluster/node lifecycle model | Implemented and deployed for the principal; regional rollout pending |
| Node-generated Ed25519 enrollment with hashed one-use token | Implemented and exercised on the principal; regional rollout pending |
| Signed node-to-Control heartbeat and replay rejection | Implemented and exercised on the principal; regional rollout pending |
| Desired/observed history and fail-closed placement gate | Implemented and active for the principal; regional acceptance pending |
| Signed desired revisions and last-known-good activation | Implemented and active for the principal; regional acceptance pending |
| Fleet identity revocation | Node-to-Control database revocation implemented; Control-to-Core trust rotation remains coordinated node configuration |
| Durable heartbeat, version compatibility and revision drift | Implemented for the principal; regional deployment and certification pending |
| Private central scrape of regional metrics | TLS 1.3/mTLS listener, central discovery, fleet metrics and alerts deployed for the principal; regional scrape pending |
| Cross-cluster-safe asymmetric transport credentials | Implemented with scoped Ed25519 `mvpn2`; independent regional validation pending |
| First regional acceptance and failure-isolation E2E | Future release gate; not certified |

## Regional production gate

A regional cluster remains inactive until all of the following are evidenced:

- the deployment rejects Control, database, Authentik and private CA material;
- management TLS verifies the expected hostname and is reachable only from the
  principal private network;
- unsigned, wrongly signed, expired and replayed operations fail;
- Control can add, inspect and remove a test peer idempotently;
- every enabled transport passes authentication, real traffic, DNS, revocation,
  kill-switch and cleanup tests;
- metrics reach central Prometheus without a public metrics listener;
- restart, abrupt stop and Control outage preserve or clean state as specified;
- revocation/rotation and rollback procedures have been exercised; and
- the node is activated only after observed health and certification match the
  intended configuration.

The executable deployment baseline is [DEPLOYMENT_PROFILES.md](../deploy/DEPLOYMENT_PROFILES.md).
API operations are defined in [openapi.yaml](openapi.yaml), and private metrics
operations are defined in [OBSERVABILITY.md](../deploy/OBSERVABILITY.md).

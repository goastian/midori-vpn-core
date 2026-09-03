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
region as separate servers, but they do not share live tunnel state. A future
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
plain HTTP are prohibited in production. The Core HTTP port and `/metrics` are
not Internet-facing.

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
timestamps. `peers.provision_operation_id` preserves the operation that owns
each completed session. A pending retry returns
`409 connection_in_progress` with `Retry-After`; a completed retry returns the
same session and sensitive configuration rather than allocating again.
Startup/periodic reconciliation of stalled rows remains a separate phase.

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
operations are introduced, a failed Core removal returns an explicit retryable
failure and leaves the device active.

A successful connection or replacement follows this order:

1. Control authenticates the user, locks the user, device and key, then
   revalidates quota and target capacity inside one database transaction.
2. Control writes a pending operation and reserves target capacity atomically.
3. Control signs an idempotent add-peer request using that operation UUID.
4. Core applies or recognizes the operation and returns its stable address.
5. Control records `core_applied`, creates the new peer, retires the previous
   database session, adjusts cross-server counters and marks the operation
   completed in one transaction.
6. Control removes the exact previous Core operation. A failure becomes
   `cleanup_pending` without losing either operation owner.

Only a definitive Core rejection releases a pending reservation immediately;
ambiguous transport or persistence failures retain durable state for the
reconciler. Reconciliation compares central active peers with a successfully
observed signed Core peer list. It must be idempotent: retrying a completed
operation cannot allocate another address or count the same peer twice.

There is no cross-cluster replication of WireGuard runtime state. Moving a
device to another server creates a new placement and removes the old one after
the new placement succeeds.

## Signed desired configuration

The implemented API signs each Control request, but it does not yet distribute
a versioned desired-configuration bundle. Before unattended regional rollout,
Control must issue a deterministic signed bundle containing at least:

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

1. Create the node on a dedicated host and generate node-local secrets there.
2. Provision the Control public key and private management-network trust.
3. Issue the management TLS certificate for the exact node hostname.
4. Add the hostname to the principal `CORE_ALLOWED_HOSTS` allowlist.
5. Register the server and explicit transport rows as inactive.
6. Verify signed peer operations, replay rejection, statistics and cleanup.
7. Mark only certified transports healthy, then activate the server.

The existing admin identity registry updates the Redis attached to the
principal process. Regional nodes use independent Redis instances, so it is not
yet a fleet-wide revocation channel. Until signed trust bundles are
implemented, Control-key rotation or emergency revocation on regional nodes is
a coordinated configuration deployment followed by verification on every
node. No document or UI may claim instantaneous fleet revocation before that
gate is closed.

Node-originated enrollment and heartbeat will use a node-specific identity
whose private key is generated and retained on that node. A one-time enrollment
credential may authorize only creation of that node record and expires after
first use. It is not a reusable fleet token.

## Credential boundary for WSS, MASQUE and proxy

The current token implementation uses `CREDENTIAL_SIGNING_SECRET`; therefore a
regional node that verifies WSS or MASQUE credentials currently needs shared
HMAC material. A single global HMAC secret would let a compromised region mint
credentials accepted elsewhere and is not the target architecture.

Before enabling those transports on multiple independent clusters, credential
verification must use either Control-signed asymmetric tokens whose private key
remains on the principal, or a distinct per-cluster HMAC key with an explicit
audience and cluster/server binding. Asymmetric verification is preferred
because regional nodes then receive only a public key. Existing tokens must
remain short-lived and bound to their audience, user, peer and server UUID.

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

The current schema has `vpn_servers` and `vpn_server_transports` but no cluster,
revision, version or durable last-seen model. Admin ping is an on-demand probe,
not a heartbeat. Those additions require a future migration and API contract
update; they are not silently emulated with transport metadata.

## Observability

The principal Prometheus instance is the aggregation point. It scrapes every
regional Core over the authenticated private management network, never through
public Nginx. Labels are bounded to cluster, node and protocol; user IDs, peer
keys, client IPs and destination addresses are prohibited.

Control must expose fleet-level desired/observed revision drift, last report,
capacity, provisioning failures and circuit-breaker state. Each node exposes
local request latency, replay failures, WireGuard capacity and transport health.
Grafana remains loopback-only and administrator access uses an SSH tunnel or an
equivalent private channel.

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
| Persistent cluster/node lifecycle model | Not implemented |
| Signed desired revisions and last-known-good activation | Not implemented |
| Automated enrollment and fleet trust rotation/revocation | Not implemented |
| Durable heartbeat, version compatibility and revision drift | Not implemented |
| Private central scrape of regional metrics | Designed, not deployed |
| Cross-cluster-safe asymmetric transport credentials | Not implemented |
| First regional acceptance and failure-isolation E2E | Paused; not certified |

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

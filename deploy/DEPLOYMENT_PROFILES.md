# Deployment profiles and privilege boundary

This is the executable deployment baseline for the topology defined in
[`docs/CENTRAL_CONTROL_ARCHITECTURE.md`](../docs/CENTRAL_CONTROL_ARCHITECTURE.md).
The regional script does not by itself certify a node. Signed enrollment,
heartbeat, desired-state polling, last-known-good activation, transport-token
verification and private fleet observability are part of the current local
implementation; the independent-server acceptance gate remains separate.

MidoriVPN uses two explicit server profiles. A service is never promoted to a
more privileged execution level merely because deployment is easier there.
The required order is:

1. **Rootless Podman** when the service passes its functional and security
   checks in a user namespace.
2. **Rootful Podman** with dropped capabilities and read-only filesystems when
   a kernel data-plane feature cannot operate rootless.
3. **Hardened host systemd service** only when the same feature cannot operate
   correctly in a rootful container. The failed rootful probe and rollback
   procedure must be recorded before using this exception.

Nginx, Certbot and firewalld remain host infrastructure because they manage
host-wide ingress, certificates and firewall policy. Development toolchains
always remain rootless.

## Principal profile: Control plus one local Core

The principal server runs one rootless Podman pod containing PostgreSQL,
PgBouncer, Redis, the Control-enabled Core API and the Control SPA. PgBouncer
uses transaction pooling and SCRAM-SHA-256 authentication; its generated
configuration and credential file live only in a private tmpfs. Core connects
to PostgreSQL exclusively through the pooler. The same Core process
also owns the local WireGuard interface and therefore represents the first VPN
exit node. Only loopback HTTP ports are published; host Nginx is the sole
public TLS entry point.

Set `DEPLOYMENT_PROFILE=principal`, choose a unique lowercase
`CORE_NODE_NAME`, and run `scripts/deploy-pod.sh` as the dedicated unprivileged
service account. Build the pinned pooler image first with:

```text
podman build -f deploy/pgbouncer/Containerfile \
  -t localhost/midorivpn-pgbouncer:2.0.0 .
```

Validate the pooler against an isolated PostgreSQL instance before deployment:

```text
PGBOUNCER_IMAGE=localhost/midorivpn-pgbouncer:2.0.0 \
CORE_IMAGE=localhost/midori-vpn-core:2.0.0 \
POSTGRES_IMAGE=<postgres-18-image-by-digest> \
bash scripts/test-pgbouncer.sh
```

The principal uses four distinct database identities: a no-login owner, a
one-shot migrator, a DML-only runtime role, and a PgBouncer console
administrator. The PostgreSQL bootstrap administrator is reserved for the
idempotent role policy and recovery. `scripts/deploy-pod.sh` applies
`deploy/postgres/configure-roles.sql`, runs migrations directly on port 5432,
then starts Core through transaction-pooled port 6432. Privileged database
credentials are removed from the generated Core and Control environment files
and those temporary files are mode 0600 and deleted on exit.

The checked-in starting envelope is 16 Core connections, 16 normal PgBouncer
backends, four reserve backends and a 24-backend database ceiling. Treat those
as measured deployment inputs, not universal PostgreSQL tuning constants;
rerun the DB-02 pool and lock gates before increasing them.

PostgreSQL operations, encrypted backup/restore and incident steps are in
`deploy/POSTGRESQL.md`.

For an existing Quadlet deployment, adapt
`deploy/pgbouncer/control-pgbouncer.container.example` to the service account
and install `deploy/pgbouncer/control-api.container.d/30-pgbouncer.conf.example`
as a drop-in for Core. The dependency and `Notify=healthy` gate prevent Core
from starting before the pooler passes its local probe.

The principal has the cluster signing identity:

```text
CONTROL_NODE_ID=<cluster-control-identity>
CONTROL_NODE_PRIVATE_KEY=<private-ed25519-key>
NODE_AUTHORIZED_KEYS=<cluster-control-identity>=<public-ed25519-key>
TRANSPORT_TOKEN_ISSUER=https://vpn.example.test
TRANSPORT_TOKEN_AUTHORIZED_KEYS=<cluster-control-identity>=<public-ed25519-key>
ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS=false
CONTROL_DATA_ENCRYPTION_KEY=<canonical-base64-32-byte-key>
```

The private key is present only on the principal. The local Core trusts its
matching public key through `NODE_AUTHORIZED_KEYS` just like every remote
Core. PostgreSQL and the Control-only Redis are not deployed on regional
nodes. If the principal also hosts proxy, WSS or MASQUE, set its exact
`TRANSPORT_CLUSTER_ID` and the same `vpn_servers` UUID in each enabled
transport's server-ID variable.

The principal Core is also modeled as an enrolled node. Its outbound identity
is distinct from the Control signing identity above and uses the same contract
as regional nodes:

```text
NODE_CONTROL_URL=https://vpn.example.test
CORE_NODE_ID=<pre-created-node-uuid>
CORE_NODE_STATE_DIR=/var/lib/midorivpn-node
CORE_NODE_ENROLLMENT_TOKEN_FILE=/var/lib/midorivpn-node/enrollment-token
CORE_NODE_MAX_PEERS=100
NODE_SECRET_FINGERPRINTS=
NODE_EXTERNAL_TRANSPORTS=openvpn,ikev2
```

The host state directory must be `0700` and an initial token file must be a
regular `0600` file. After successful enrollment, Core removes that token while
retaining `identity.json` at `0600`. Subsequent restarts reuse the same key.
For a brand-new principal only, these six node-identity variables may all be
empty for the first bootstrap so the administrator API can create the cluster,
node and token. Configure the complete set and restart immediately afterward;
the bootstrap instance remains ineligible for modeled placement and is not a
release-ready state. Partial configuration always fails startup.

`NODE_EXTERNAL_TRANSPORTS` declares host gateways that belong to the logical
node but execute outside Core. It accepts only unique lowercase `openvpn`
and/or `ikev2` values. In-process WireGuard/WSS/MASQUE/proxy capabilities remain
derived from their actual runtime switches. An external protocol must not be
declared unless its private health adapter is installed; central health and
certification gates remain independently fail-closed.

Transport placement combines three independent authorities: the signed desired
bundle must enable the protocol, the latest signed node observation must match
the active revision and report a healthy compatible node, and Control's
`vpn_server_transports` inventory must have a fresh healthy probe. OpenVPN and
IKEv2 additionally require central `metadata.certified=true`. A node-reported
`certified` value is retained only for protocol compatibility and never grants
or revokes certification; nodes cannot certify themselves.

The principal also requires its dedicated observability server identity,
public client-CA certificate and exact Prometheus client URI SAN. TCP/9443 is
attached to `OBSERVABILITY_NETWORK`, never public ingress. The Prometheus
client key stays outside the Core environment and is mounted only in the
rootless Prometheus container.

## Regional profile: Core exit node

Every additional server runs a rootless Core without `DATABASE_URL`,
`AUTHENTIK_CLIENT_ID`, client-CA signing key or Control SPA. It receives:

```text
CONTROL_NODE_ID=
CONTROL_NODE_PRIVATE_KEY=
CONTROL_DATA_ENCRYPTION_KEY=
NODE_AUTHORIZED_KEYS=<cluster-control-identity>=<public-ed25519-key>
NODE_AUTH_REDIS_URL=<node-local-authenticated-redis-url>
TRANSPORT_TOKEN_ISSUER=https://vpn.example.test
TRANSPORT_TOKEN_AUTHORIZED_KEYS=<cluster-control-identity>=<public-ed25519-key>
TRANSPORT_CLUSTER_ID=<control-issued-cluster-uuid>
ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS=false
NODE_EXTERNAL_TRANSPORTS=
```

Set `DEPLOYMENT_PROFILE=core-node`, choose a unique `CORE_NODE_NAME`, and run
`scripts/VPN/deploy-core-node.sh` as the dedicated unprivileged service
account. Configure `NODE_CONTROL_URL`, `CORE_NODE_ID`,
`CORE_NODE_STATE_DIR`, `CORE_NODE_ENROLLMENT_TOKEN_FILE` and
`CORE_NODE_MAX_PEERS` together. `NODE_SECRET_FINGERPRINTS` is optional and uses
comma-separated `name=64-lowercase-hex` references; it never contains the
underlying secret. The script validates the UUID and HTTPS origin,
requires the host state directory to be `0700`, accepts only a regular `0600`
token file, and mounts the state directory at the exact configured container
path. It fails closed if Control, database, Authentik or CA signing secrets are
present.

Regional nodes normally leave `NODE_EXTERNAL_TRANSPORTS` empty until an
external gateway and its private health adapter are installed on that node.

The regional receives no credential signing secret or private key. Its proxy,
WSS and MASQUE gateways accept only `mvpn2` credentials signed by one of the
dedicated public keys and bound to `TRANSPORT_CLUSTER_ID` plus the configured
server UUID. `CREDENTIAL_SIGNING_SECRET` must be empty in this production
profile.

Configure `OBSERVABILITY_MTLS_PORT=9443`, an exact RFC1918
`OBSERVABILITY_HOST_BIND`, the node-specific server certificate/key, public
observability client-CA certificate and exact authorized Prometheus SPIFFE URI.
The server key must be a regular `0600` file. The deployment script refuses a
Prometheus client certificate or key on the regional and publishes 9443 only on
the declared private address. Firewall and routing must restrict that address
to the principal management network.

The node-local Redis provides replay protection for Control-to-Core calls. It
is not the Control data store and must not expose a host port. Control calls the
regional Core over HTTPS and signs every peer/statistics request with Ed25519,
timestamp and a single-use nonce. Node-to-Control enrollment and heartbeat use
the principal Redis for a separate nonce domain. “Connecting a Core to
Control” therefore consists of:

1. creating the inactive cluster and `enrolling` node in Control;
2. issuing and privately installing its one-use enrollment token;
3. provisioning the Control public key in the Core;
4. issuing a TLS certificate for the Core management hostname;
5. adding that hostname to `CORE_ALLOWED_HOSTS` on the principal;
6. starting Core and confirming token removal plus signed heartbeat storage;
7. registering the server and its explicit transport rows in Control; and
8. verifying signed add/remove-peer and statistics calls before activation.

No database credential, Authentik secret, Control data-encryption key or Control
private signing key is copied to a regional node. Node management ports are reachable only through
TLS and an ingress allowlist restricted to the principal server.

Revoking the enrolled node blocks its node-to-Control heartbeat immediately in
the central database and invalidates unused enrollment tokens. Control-to-Core
authorized request keys remain explicit node-local configuration, so emergency
rotation of that management trust is a coordinated deployment to every Core.
Transport credentials use a separate Ed25519 public trust store; no regional
possesses the issuer's private key.

## Gateway placement on both profiles

WireGuard Core, WSS, MASQUE, PostgreSQL, Redis and Control remain rootless.
OpenVPN/DCO and strongSwan/XFRM use rootful system Quadlets with host networking,
`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`, a read-only image and
only their PKI and health directories mounted. Their host service examples are
rollback fallbacks, not the default deployment.

The rootful gateway writes an atomic file below `/run/midorivpn-health`; the
rootless Core mounts that directory read-only. The gateway receives gateway
certificates and the public client CA, never the client CA signing key. A host
service and its corresponding rootful Quadlet have `Conflicts=` and must never
run simultaneously.

OpenVPN and IKEv2 remain `certified=false` and their public firewall rules stay
closed until authenticated client E2E, revocation, DNS, kill-switch and cleanup
tests pass.

## New-node acceptance gate

- Rootless Core starts without PostgreSQL/Auth/Control configuration.
- Node-local Redis is private and replay tests reject a reused nonce.
- Core generates one stable private Ed25519 identity locally; Control stores
  only the public key and a digest of the consumed enrollment token.
- A successful enrollment removes the node-local plaintext token, and a replay,
  expired token, reused token or revoked node fails closed.
- Signed heartbeats update durable observed history without claiming transport
  certification or version compatibility.
- Unsigned and wrongly signed management calls return `401`.
- Control can add a test peer, read real statistics and remove that peer.
- Node health and transport health appear in the protected admin endpoint.
- The dedicated TLS 1.3/mTLS observability endpoint rejects no-certificate,
  wrong-URI and TLS 1.2 clients; it is reachable only from the principal.
- Central HTTP discovery includes the active regional, excludes inactive and
  revoked inventory, and preserves stale active targets for alerting.
- Heartbeat, revision drift, version, signature/replay, capacity and pending
  operation signals reach the private principal Prometheus.
- Public user APIs expose only enabled, healthy and certified transports.
- Restart and abrupt-stop tests leave no interface, route, XFRM state or
  gateway-specific nftables table behind.

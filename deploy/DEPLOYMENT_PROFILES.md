# Deployment profiles and privilege boundary

This is the executable deployment baseline for the topology defined in
[`docs/CENTRAL_CONTROL_ARCHITECTURE.md`](../docs/CENTRAL_CONTROL_ARCHITECTURE.md).
The regional script does not by itself certify a node or implement the future
signed desired-state, heartbeat and fleet revocation contracts described there.

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
POSTGRES_IMAGE=<postgres-18-image-by-digest> \
bash scripts/test-pgbouncer.sh
```

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
CONTROL_DATA_ENCRYPTION_KEY=<canonical-base64-32-byte-key>
```

The private key is present only on the principal. The local Core trusts its
matching public key through `NODE_AUTHORIZED_KEYS` just like every remote
Core. PostgreSQL and the Control-only Redis are not deployed on regional
nodes.

## Regional profile: Core exit node

Every additional server runs a rootless Core without `DATABASE_URL`,
`AUTHENTIK_CLIENT_ID`, client-CA signing key or Control SPA. It receives:

```text
CONTROL_NODE_ID=
CONTROL_NODE_PRIVATE_KEY=
CONTROL_DATA_ENCRYPTION_KEY=
NODE_AUTHORIZED_KEYS=<cluster-control-identity>=<public-ed25519-key>
NODE_AUTH_REDIS_URL=<node-local-authenticated-redis-url>
```

Set `DEPLOYMENT_PROFILE=core-node`, choose a unique `CORE_NODE_NAME`, and run
`scripts/VPN/deploy-core-node.sh` as the dedicated unprivileged service
account. The script fails closed if Control, database, Authentik or CA signing
secrets are present.

The node-local Redis provides replay protection. It is not the Control data
store and must not expose a host port. Control calls the regional Core over
HTTPS and signs every peer/statistics request with Ed25519, timestamp and a
single-use nonce. “Connecting a Core to Control” therefore consists of:

1. provisioning the Control public key in the Core;
2. issuing a TLS certificate for the Core management hostname;
3. adding that hostname to `CORE_ALLOWED_HOSTS` on the principal;
4. registering the server and its explicit transport rows in Control; and
5. verifying signed add/remove-peer and statistics calls before activation.

No database credential, Authentik secret, Control data-encryption key or Control
private signing key is copied to a regional node. Node management ports are reachable only through
TLS and an ingress allowlist restricted to the principal server.

The current admin identity registry is local to the Redis instance used by its
Core process. It does not yet propagate revocation into independent regional
Redis instances. Until signed trust revisions are implemented, key rotation or
revocation is an explicit coordinated configuration update on every node.

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
- Unsigned and wrongly signed management calls return `401`.
- Control can add a test peer, read real statistics and remove that peer.
- Node health and transport health appear in the protected admin endpoint.
- Public user APIs expose only enabled, healthy and certified transports.
- Restart and abrupt-stop tests leave no interface, route, XFRM state or
  gateway-specific nftables table behind.

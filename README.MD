# Midori VPN 2.0.0

Midori VPN is a Linux-first VPN platform built around WireGuard. The project
includes the Go Core API, the Vue Control panel, a native Go Linux agent with a
browser-served Vue UI, and Firefox/Chromium proxy extensions.

The versioned HTTP contract is [docs/openapi.yaml](docs/openapi.yaml). Router
coverage is checked bidirectionally so documented and implemented operations
cannot drift silently.

The target topology for one central Control and independent regional Core
clusters is defined in
[docs/CENTRAL_CONTROL_ARCHITECTURE.md](docs/CENTRAL_CONTROL_ARCHITECTURE.md).
It distinguishes the implemented single-principal baseline from the remaining
regional production gates.

Version 2.0.0 is an active rework. Linux x86_64 RPM is the only Desktop target;
the abandoned Tauri/Rust and non-Linux client sources have been removed.

## Verified transports

| Transport | Public port | State |
|---|---:|---|
| WireGuard | `51820/udp` | Production, real kernel handshake |
| WireGuard over WSS | `443/tcp` | Authenticated, health-gated |
| WireGuard over MASQUE | `443/udp` | RFC 9298 CONNECT-UDP, TLS 1.3, authenticated, health-gated |
| HTTPS CONNECT proxy | configured TLS endpoint | Browser extension only, scoped token |
| OpenVPN DCO | `1194/udp` | Native Linux client and rootful gateway certified; advertised only while healthy and explicitly certified |
| IKEv2 | `500/udp`, `4500/udp` | Native EAP-TLS client and rootful gateway certified; advertised only while healthy and explicitly certified |

OpenVPN and IKEv2 share a client-certificate authority. Devices generate an
ECDSA P-256 private key locally and submit only a signed CSR to Core. Core
stores the resulting public certificate and revocation state; device private
keys are never accepted by the API or stored in PostgreSQL. Operators must
configure `VPN_CLIENT_CA_CERT` and `VPN_CLIENT_CA_KEY` before either transport
can be enabled. The public CA and CRL are served from `/pki/client-ca.pem` and
`/pki/client.crl`.

Control persists client installations separately from VPN sessions. A
registered device is keyed by `(user_id, client_instance_id)`, while active
peers and client certificates reference its internal `device_id`. Historical
clients without an installation UUID remain isolated legacy records and are
never merged solely because two hostnames match. Adapter references are
non-unique, HMAC-derived secondary observations; raw MAC addresses are not API
fields and are never stored.

Smart mode orders the healthy WireGuard family (`wireguard`, `wss`, `masque`)
by priority and accepts a connection only after a WireGuard handshake. OpenVPN
and IKEv2 are explicit user selections when their server capability is healthy
and certified. There are no simulated sessions or implicit transport ports.

## Source repositories

- [Core](https://github.com/goastian/midori-vpn-core): API, gateways, database
  and deployment operations.
- [Control](https://github.com/goastian/midori-vpn-control): administration and
  user SPA.
- [Desktop](https://github.com/goastian/midori-vpn-desktop): Linux agent, tray,
  Vue client and RPM packaging.
- [Browser extension](https://github.com/goastian/midorivpn-extension): Firefox,
  Midori and Chromium HTTPS proxy client.

The primary Core tree is organized as follows:

```text
cmd/vpn-core/                 Core and Control process
internal/                     Auth, API, database, gateways, repositories, WireGuard
internal/db/migrations/       Immutable PostgreSQL migrations and rollbacks
deploy/                       Nginx, sysctl and protocol operations
scripts/                      Rootless Podman build, validation and deployment tools
```

## Supported toolchain

- Rootless Podman; Docker and host-installed language toolchains are not part of the supported workflow.
- Go 1.27.
- Node.js 24 LTS and npm 12.
- PostgreSQL 18.6.
- Redis 8.10.1.
- Alpine 3.24 runtime.

TypeScript stays at 6.0.3 while the current `typescript-eslint` peer contract requires TypeScript `<6.1`. The incompatibility is checked rather than bypassed.

## Configuration

Copy `.env.example` to a private `0600` environment file and replace every `<required-...>` value. Core rejects incomplete production configuration; setup scripts do not generate secrets or guess production hosts.

Important security groups:

- `CONTROL_NODE_ID`, `CONTROL_NODE_PRIVATE_KEY`, `NODE_AUTHORIZED_KEYS`: Ed25519 node identities.
- `NODE_AUTH_REDIS_URL`: shared nonce/revocation state for signed requests.
- `CREDENTIAL_SIGNING_SECRET`: short-lived proxy and tunnel credentials.
- `CONTROL_DATA_ENCRYPTION_KEY`: principal-only, canonical base64 for exactly 32 random bytes; encrypts recoverable WireGuard PSKs in PostgreSQL and must be backed up separately.
- `DATABASE_URL` / `POSTGRES_*` and authenticated `REDIS_URL` / `REDIS_*`.
- `WSS_TUNNEL_*` and `MASQUE_*`: disabled explicitly unless their gateways are configured.
- `CORE_ALLOWED_HOSTS`, `TRUSTED_PROXIES`, `CORS_ALLOWED_ORIGINS`: mandatory production boundaries.

Do not place secrets in image build arguments, Git, logs or release artifacts. The
first Control startup after migration 16 encrypts legacy PSKs in bounded,
restart-safe batches and clears each plaintext value only after an authenticated
round trip. Validate that migration on staging and back up both PostgreSQL and
`CONTROL_DATA_ENCRYPTION_KEY` before migrating the principal.

## Rootless development and validation

The unified runner discovers the Control, Desktop and extension repositories
when they are nested under Core or cloned beside it. It rejects invocation from
an unrelated directory instead of silently running a command at the Core root.

```bash
# Build pinned development images
bash scripts/pod.sh build-images

# Core
bash scripts/pod.sh go test -race ./cmd/... ./internal/...
bash scripts/pod.sh go vet ./cmd/... ./internal/...
bash scripts/pod.sh staticcheck ./cmd/... ./internal/...
bash scripts/pod.sh govulncheck ./cmd/... ./internal/...

# Migration chain and rollback on disposable PostgreSQL 18
bash scripts/test-migrations.sh

# Prohibited debt markers, migration pairs and dependency graph
bash scripts/pod.sh debt

# Runner path/layout contract without starting containers
bash scripts/test-pod-runner.sh
```

Each frontend repository documents its own check command and also runs
`npm audit --audit-level=high`. Linux release packaging performs Go and npm
builds inside a rootless Podman RPM builder.

## Deployment

`scripts/deploy-pod.sh` consumes a complete environment and creates a rootless Podman pod. The staging installation uses systemd Quadlets so database, Redis, API and web services are independently supervised.

Principal and regional profiles, their privilege boundaries and their
acceptance gate are described in `deploy/DEPLOYMENT_PROFILES.md`.

Host-facing topology:

| Router/firewalld | Host/rootless mapping | Purpose |
|---|---|---|
| `443/tcp` | Host Nginx → loopback API/web | HTTPS API, UI and WSS |
| `443/udp` | firewalld → `8443/udp` → container `443/udp` | MASQUE without relaxing privileged-port sysctl |
| `51820/udp` | Podman → Core | Direct WireGuard |

Never expose PostgreSQL, Redis, Core HTTP or Control container HTTP publicly. MASQUE uses the Let's Encrypt certificate mounted read-only; `scripts/reload-masque-certificate.sh` is installed as a Certbot deploy hook so renewed certificates are loaded.

Operational helpers:

```bash
scripts/configure-quadlet-masque.sh  # backup, configure and restart with rollback
scripts/upgrade-quadlet-redis.sh     # SAVE, volume export and Redis major upgrade
scripts/setup-core-host.sh           # validate/install host Nginx and Certbot inputs
scripts/render-observability.sh      # render private Prometheus/Grafana Quadlets
scripts/check-observability.sh       # validate rules, dashboard and private binds
```

Prometheus and Grafana share the existing private Core Podman network but
publish their administrative ports only on `127.0.0.1`. Public Nginx continues
to return `404` for `/metrics`; operators reach Grafana through an SSH tunnel.
See `deploy/OBSERVABILITY.md` for rendering, deployment and rollback.

## Authentication and capability model

- Users authenticate with Authentik OAuth 2.0/OIDC Authorization Code + PKCE.
- Core-to-node requests use Ed25519 signatures with timestamp, nonce, replay protection and revocation.
- Browser proxy credentials use audience `vpn-proxy` and short expiry.
- WSS/MASQUE credentials use audience `vpn-tunnel` and are bound to user, active peer and server UUID.
- Clients receive only enabled transports whose latest health probe is `healthy`.
- The normalized `vpn_server_transports` table is the sole transport contract; retired proxy/WSS columns were removed by migration 9.

## Client and extension

- Linux installation, signature verification and RPM build:
  [Desktop README](https://github.com/goastian/midori-vpn-desktop/blob/main/README.md).
- Control development:
  [Control README](https://github.com/goastian/midori-vpn-control/blob/main/README.md).
- Firefox/Chromium extension build:
  [extension README](https://github.com/goastian/midorivpn-extension/blob/main/README.md).
- WSS operations: `deploy/WSS_TUNNEL.md`.
- MASQUE operations: `deploy/MASQUE.md`.

## Branch and release policy

Release artifacts are produced only from the approved annotated version tag and
clean source revisions recorded in the release manifest. Working branches are
not release inputs. Changelogs must be updated for every release change.

The required artifact set, trust identities, SBOM/provenance evidence and
store-signing gates are defined in `docs/RELEASE_SUPPLY_CHAIN.md`. Preparing a
release does not authorize a tag, registry upload, store submission or public
GitHub release.

## License

AGPL-3.0-or-later. See `LICENSE`.

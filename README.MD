# Midori VPN 2.0.0

Midori VPN is a Linux-first VPN platform built around WireGuard. The workspace contains the Go Core/Control API, the Vue Control panel, a native Go Linux agent with a browser-served Vue UI, and Firefox/Chromium proxy extensions.

Version 2.0.0 is an active rework. Linux x86_64 RPM is the only production client target. Windows and macOS source is preserved, but their build and release jobs remain blocked until each native path is certified.

## Verified transports

| Transport | Public port | State |
|---|---:|---|
| WireGuard | `51820/udp` | Production, real kernel handshake |
| WireGuard over WSS | `443/tcp` | Authenticated, health-gated |
| WireGuard over MASQUE | `443/udp` | RFC 9298 CONNECT-UDP, TLS 1.3, authenticated, health-gated |
| HTTPS CONNECT proxy | configured TLS endpoint | Browser extension only, scoped token |
| OpenVPN DCO | `1194/udp` | Not advertised until a real gateway/client is deployed |
| IKEv2 | `500/udp`, `4500/udp` | Not advertised until a real gateway/profile flow is deployed |

Smart mode tries only healthy advertised transports and accepts a connection only after a WireGuard handshake. There are no simulated sessions or implicit transport ports.

## Workspace

```text
cmd/vpn-core/                 Core and Control process
internal/                     Auth, API, database, gateways, repositories, WireGuard
internal/db/migrations/       Immutable PostgreSQL migrations and rollbacks
midori-vpn-control/           Vue administration and user panel
midori-vpn-desktop/           Linux agent, Vue client and RPM packaging
midorivpn-extension/          Firefox and Chromium HTTPS proxy extension
deploy/                       Nginx, sysctl and protocol operations
scripts/                      Rootless Podman build, validation and deployment tools
.projects/                    Permanent local plans, architecture, audits and incidents
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
- `DATABASE_URL` / `POSTGRES_*` and authenticated `REDIS_URL` / `REDIS_*`.
- `WSS_TUNNEL_*` and `MASQUE_*`: disabled explicitly unless their gateways are configured.
- `CORE_ALLOWED_HOSTS`, `TRUSTED_PROXIES`, `CORS_ALLOWED_ORIGINS`: mandatory production boundaries.

Do not place secrets in image build arguments, Git, `.projects`, logs or release artifacts.

## Rootless development and validation

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

# Frontends
(cd midori-vpn-control && bash ../scripts/pod.sh npm run check)
(cd midori-vpn-desktop && bash ../scripts/pod.sh npm run check)
(cd midorivpn-extension && bash ../scripts/pod.sh npm run check)
```

All npm projects also run `npm audit --audit-level=high`. Linux release packaging performs Go and npm builds inside a rootless Podman RPM builder.

## Deployment

`scripts/deploy-pod.sh` consumes a complete environment and creates a rootless Podman pod. The staging installation uses systemd Quadlets so database, Redis, API and web services are independently supervised.

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
```

## Authentication and capability model

- Users authenticate with Authentik OAuth 2.0/OIDC Authorization Code + PKCE.
- Core-to-node requests use Ed25519 signatures with timestamp, nonce, replay protection and revocation.
- Browser proxy credentials use audience `vpn-proxy` and short expiry.
- WSS/MASQUE credentials use audience `vpn-tunnel` and are bound to user, active peer and server UUID.
- Clients receive only enabled transports whose latest health probe is `healthy`.
- The normalized `vpn_server_transports` table is the sole transport contract; retired proxy/WSS columns were removed by migration 9.

## Client and extension

- Linux installation, signature verification and RPM build: `midori-vpn-desktop/README.md`.
- Control development: `midori-vpn-control/README.md`.
- Firefox/Chromium extension build: `midorivpn-extension/README.md`.
- WSS operations: `deploy/WSS_TUNNEL.md`.
- MASQUE operations: `deploy/MASQUE.md`.

## Branch and release policy

Development is performed only on local branch `dev-wedc`. Nothing is pushed or made public from this workspace. Generated artifacts are signed and verified locally before transfer to the test client. Changelogs must be updated for every release change.

## License

AGPL-3.0-or-later. See `LICENSE`.

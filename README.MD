# Midori VPN Core

WireGuard VPN management daemon + control panel API written in **Go**, with a **Vue 3** frontend.

## Architecture

```
cmd/vpn-core/main.go        → entrypoint (WireGuard + Control API)
internal/
  api/                       → chi router, CORS, rate limiting middleware
  respond/                   → shared JSON response helpers (JsonOK, JsonError, SafeError)
  core/                      → WireGuard core HTTP handlers + X-Core-Token middleware
  control/                   → Control API handlers, OAuth, core-client, background jobs, WebSocket hub
  auth/                      → JWT/JWKS validation (Authentik), JIT user provisioning
  config/                    → environment-based configuration
  crypto/                    → Curve25519 keypair generation
  db/                        → PostgreSQL connection pool (pgx) + migrations
  ippool/                    → automatic IP allocation in 10.8.0.0/16
  models/                    → data models (User, VPNServer, Peer, AuditLog)
  repo/                      → repository pattern for DB access
  wg/                        → WireGuard manager (wgctrl + netlink)
migrations/                  → PostgreSQL schema migrations
midori-vpn-control/          → Vue 3 + TypeScript frontend (panel de control)
```

## Components

### VPN Core API
Low-level WireGuard peer management. Protected by shared secret (`X-Core-Token`).

### Control API
User-facing API for managing VPN connections, servers and audit logs. Protected by JWT tokens from Authentik. Enabled automatically when `DATABASE_URL` and `AUTHENTIK_CLIENT_ID` are set.

### Control Frontend (`midori-vpn-control/`)
Vue 3 + TypeScript SPA with OAuth2/OIDC login flow (PKCE) against `accounts.astian.org`. Features automatic token refresh and state validation.

## Requirements

- **Docker** (recommended) — builds and runs everything in containers
- Or: **Go 1.22+**, **Node.js 20+**, PostgreSQL 16+, Redis 7+, Linux with WireGuard

## Quick Start (Docker)

```bash
cp .env.default .env
# Edit .env — set DOMAIN, VPN_CORE_TOKEN, CORE_ALLOWED_HOSTS,
# DATABASE_URL/REDIS_URL passwords, WG_ENDPOINT and AUTHENTIK_CLIENT_ID

# Development (builds from source, includes PostgreSQL + Redis)
docker compose -f docker-compose-dev.yml up --build

# Production with bundled nginx TLS reverse proxy
docker compose -f docker-compose-prod.yml up -d
```

## TLS For Control And Core Nodes

`vpn-core` listens on plain HTTP inside the container (`VPN_CORE_PORT`, default
`:8080`). TLS is enabled by putting nginx in front of the container and exposing
`443 -> vpn-core:8080`. `docker-compose-prod.yml` already includes nginx and
expects certificates at:

```text
certs/fullchain.pem
certs/privkey.pem
```

Control calls registered Core nodes over HTTPS by default. In production keep:

```env
CORE_TLS_SKIP_VERIFY=false
CORE_ALLOW_INSECURE_HTTP=false
CORE_ALLOWED_HOSTS=vpn.example.com,core1.example.com,core2.example.com
```

`CORE_ALLOWED_HOSTS` must contain hostnames only, without scheme or port. Use
public certificates (for example Let's Encrypt) on every Core node, or install
your private CA in the container trust store. Do not use
`CORE_TLS_SKIP_VERIFY=true` in production; startup rejects it.

Public ports per node:

| Port | Purpose |
|---|---|
| `443/tcp` | Control/Core API through TLS |
| `51820/udp` | WireGuard |
| `8888/tcp` | Optional authenticated HTTP CONNECT proxy |

Do not expose `8080/tcp` publicly. It should only be reachable by the local
reverse proxy or an internal Docker network.

### Control + Primary Core `.env`

Example for a node that runs both Control and a local Core at
`vpn.example.com`:

```env
APP_ENV=production
DOMAIN=vpn.example.com

VPN_CORE_PORT=8080
VPN_CORE_TOKEN=<strong-primary-core-token>

WG_PORT=51820
WG_ENDPOINT=vpn.example.com

POSTGRES_PASSWORD=<postgres-password>
REDIS_PASSWORD=<redis-password>
DATABASE_URL=postgres://midori:<postgres-password>@postgres:5432/midori_vpn?sslmode=disable
REDIS_URL=redis://:<redis-password>@redis:6379/0

AUTHENTIK_ISSUER=https://accounts.astian.org/application/o/midorivpn
AUTHENTIK_CLIENT_ID=<client-id>
AUTHENTIK_CLIENT_SECRET=<client-secret>

PUBLIC_BASE_URL=https://vpn.example.com
CORS_ALLOWED_ORIGINS=https://vpn.example.com

CORE_TLS_SKIP_VERIFY=false
CORE_ALLOW_INSECURE_HTTP=false
CORE_ALLOWED_HOSTS=vpn.example.com,core1.example.com,core2.example.com
```

### External Core `.env`

Example for a node that only runs Core at `core1.example.com`:

```env
APP_ENV=production
DOMAIN=core1.example.com

VPN_CORE_PORT=8080
VPN_CORE_TOKEN=<strong-unique-core1-token>

WG_PORT=51820
WG_ENDPOINT=core1.example.com

DATABASE_URL=
AUTHENTIK_CLIENT_ID=

CORE_TLS_SKIP_VERIFY=false
CORE_ALLOW_INSECURE_HTTP=false
CORE_ALLOWED_HOSTS=core1.example.com
TRUSTED_PROXIES=172.16.0.0/12
```

This node still needs nginx with a valid certificate proxying `443` to
`vpn-core:8080`. Control will authenticate to it with that node's
`VPN_CORE_TOKEN` via the `X-Core-Token` header.

### Registering Servers In Control

Create or edit servers in the Admin API/UI with these values:

| Field | Primary Core | External Core |
|---|---|---|
| Name | `Primary` | `Core 1` |
| Host | `vpn.example.com` | `core1.example.com` |
| Port | `443` | `443` |
| Endpoint | `vpn.example.com` | `core1.example.com` |
| WG Port | `51820` | `51820` |
| Public Key | `data.public_key` from `/api/v1/stats` | `data.public_key` from `/api/v1/stats` |
| Core Token | primary `VPN_CORE_TOKEN` | core1 `VPN_CORE_TOKEN` |
| Active | `true` | `true` |

Fetch a node's WireGuard public key with:

```bash
curl -H "X-Core-Token: <token>" https://core1.example.com/api/v1/stats
```

Use `data.public_key` when creating the server. The Control API also refreshes
the stored public key from `/api/v1/stats` during connection flows.

For a Core on the same machine as Control, prefer registering its public DNS
name (`vpn.example.com`, port `443`). Registering `localhost`, `127.0.0.1` or
`vpn-core:8080` requires `CORE_ALLOW_INSECURE_HTTP=true` and is intended only
for local/testing deployments.

Validation checklist:

```bash
curl https://core1.example.com/health
curl -H "X-Core-Token: <token>" https://core1.example.com/api/v1/stats
```

Then check `/api/v1/admin/servers/ping` from Control and create a connection
against each server. The returned WireGuard endpoint should be
`<server-host>:51820`.

## Environment Variables

### Application

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `production` | `production` hides internal errors, `development` shows them |

### Core (WireGuard)

| Variable | Default | Description |
|---|---|---|
| `VPN_CORE_PORT` | `8080` | HTTP API listen port |
| `VPN_CORE_TOKEN` | *(empty)* | Shared secret for `X-Core-Token` header |
| `WG_INTERFACE` | `wg0` | WireGuard interface name |
| `WG_PORT` | `51820` | WireGuard UDP listen port |
| `WG_SUBNET` | `10.8.0.0/16` | IP pool subnet |
| `WG_CONFIG_DIR` | `/etc/wireguard` | Config persistence directory |
| `WG_ENDPOINT` | *(empty)* | Public IP/hostname for peer configs |

### Control API (optional — enables user management)

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *(empty)* | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `AUTHENTIK_ISSUER` | *(empty)* | OIDC issuer URL |
| `AUTHENTIK_CLIENT_ID` | *(empty)* | Authentik OAuth2 client ID |
| `AUTHENTIK_CLIENT_SECRET` | *(empty)* | Authentik OAuth2 client secret |
| `AUTHENTIK_JWKS_URL` | *(auto from issuer)* | JWKS endpoint URL |

### Security & Limits

| Variable | Default | Description |
|---|---|---|
| `CORS_ALLOWED_ORIGINS` | `https://*.astian.org,...` | Comma-separated allowed origins |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated trusted reverse proxy IPs/CIDRs; required in production |
| `RATE_LIMIT_RPS` | `20` | Requests per second per IP (0 = disabled) |
| `RATE_LIMIT_BURST` | `40` | Burst size for rate limiter |
| `MAX_DEVICES_PER_USER` | `5` | Max active VPN connections per user (0 = unlimited) |
| `CORE_TLS_SKIP_VERIFY` | `false` | Skip TLS verification for core-to-core comms |
| `CORE_ALLOW_INSECURE_HTTP` | `false` | Allow HTTP (no TLS) for core-to-core comms in local/testing |
| `CORE_ALLOWED_HOSTS` | *(empty)* | Comma-separated core host whitelist; required in production |

## API Endpoints

Availability notes:
- `Core API` and `GET /health` are always available.
- `Auth`, `Control API`, `Admin API`, and `WebSocket` are available only when both `DATABASE_URL` and `AUTHENTIK_CLIENT_ID` are configured.

### Core API (`X-Core-Token` protected)

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check (no auth) |
| `POST` | `/api/v1/peers` | Add WireGuard peer |
| `DELETE` | `/api/v1/peers/{pubkey}` | Remove peer |
| `PUT` | `/api/v1/peers/{pubkey}` | Update peer keepalive |
| `GET` | `/api/v1/peers/{pubkey}/stats` | Peer traffic stats |
| `GET` | `/api/v1/peers` | List all peers |
| `POST` | `/api/v1/keypair` | Generate Curve25519 keypair |
| `GET` | `/api/v1/stats` | Server stats |

### Auth (public)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/auth/config` | OIDC configuration for frontend |
| `POST` | `/api/v1/auth/callback` | Exchange authorization code for tokens |
| `POST` | `/api/v1/auth/refresh` | Refresh access token using refresh token |

### Control API (JWT Bearer protected)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/control/me` | Current user profile |
| `POST` | `/api/v1/control/keypair` | Generate keypair (for browser clients) |
| `GET` | `/api/v1/control/servers` | List active VPN servers |
| `GET` | `/api/v1/control/servers/ping` | Ping all servers (latency check) |
| `POST` | `/api/v1/control/connections` | Connect to a VPN server |
| `GET` | `/api/v1/control/connections` | List my active connections |
| `DELETE` | `/api/v1/control/connections/{id}` | Disconnect from a server |
| `GET` | `/api/v1/control/connections/{id}/config` | Download WireGuard .conf file |
| `GET` | `/api/v1/control/connections/{id}/qr` | Download QR code PNG for config |
| `GET` | `/api/v1/control/audit-logs` | My audit logs |

### Admin API (JWT + admin role required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/admin/dashboard/stats` | Dashboard statistics |
| `GET` | `/api/v1/admin/users` | List all users |
| `POST` | `/api/v1/admin/users` | Create user |
| `GET` | `/api/v1/admin/users/{id}` | Get user details |
| `PUT` | `/api/v1/admin/users/{id}` | Update user |
| `DELETE` | `/api/v1/admin/users/{id}` | Delete user |
| `POST` | `/api/v1/admin/users/{id}/ban` | Ban/unban user |
| `GET` | `/api/v1/admin/servers` | List all servers (includes core_token) |
| `POST` | `/api/v1/admin/servers` | Create server |
| `PUT` | `/api/v1/admin/servers/{id}` | Update server |
| `DELETE` | `/api/v1/admin/servers/{id}` | Delete server |
| `GET` | `/api/v1/admin/peers` | List all peers |
| `DELETE` | `/api/v1/admin/peers/{id}` | Force disconnect peer |
| `GET` | `/api/v1/admin/audit-logs` | All audit logs |

### WebSocket

| Path | Description |
|---|---|
| `/ws?token=<jwt>` | Real-time stats broadcast (JWT via query param) |

## License

See [LICENSE](LICENSE) file.

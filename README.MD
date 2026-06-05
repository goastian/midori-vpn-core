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
User-facing API for managing VPN connections, servers and audit logs. Protected by JWT tokens from Authentik. Enabled automatically when Authentik is configured and the database is reachable through `DATABASE_URL` or the `POSTGRES_*` settings.

### Control Frontend (`midori-vpn-control/`)
Vue 3 + TypeScript SPA with OAuth2/OIDC login flow (PKCE) against the configured Authentik issuer. Features automatic token refresh and state validation.

## Requirements

- **Docker** (recommended) — builds and runs everything in containers
- Or: **Go 1.22+**, **Node.js 20+**, PostgreSQL 16+, Redis 7+, Linux with WireGuard

## Quick Start (Docker)

```bash
# Core-only production behind host nginx:
sudo scripts/setup-core-host.sh
docker compose -f docker-compose-prod.yml up -d

# Development (builds from source, includes PostgreSQL + Redis)
docker compose -f docker-compose-dev.yml up --build
```

## Core Behind Host Nginx

`vpn-core` listens on plain HTTP inside the container (`VPN_CORE_PORT`, default
`:8080`). In production, `docker-compose-prod.yml` publishes that HTTP API only
to host loopback:

```text
127.0.0.1:${VPN_CORE_HOST_PORT:-8085} -> vpn-core:8080
```

TLS is handled by nginx installed on the host. Run
`sudo scripts/setup-core-host.sh` to generate `.env`, install the nginx vhost,
request a Let's Encrypt certificate with Certbot, and configure renewal reloads.
Use `LETSENCRYPT_STAGING=true` for the first test run, then rerun with staging
disabled after removing the staging certificate for that domain.

Public ports per node:

| Port | Purpose |
|---|---|
| `443/tcp` | Control/Core API through TLS |
| `51820/udp` | WireGuard |
| `8888/tcp` | Optional authenticated HTTP CONNECT proxy |

Do not expose `8080/tcp` publicly. It should only be reachable by the local
host nginx through `127.0.0.1:$VPN_CORE_HOST_PORT`.

### Core-only `.env`

The setup script prompts for:

- `DOMAIN`
- `VPN_CORE_HOST_PORT`
- `VPN_CORE_TOKEN`, generated when left blank
- `POSTGRES_USER`
- `POSTGRES_DB`
- `POSTGRES_PASSWORD`, generated when left blank
- `REDIS_PASSWORD`, generated when left blank
- `WG_ENDPOINT`
- `WG_PORT`
- `CORE_ALLOWED_HOSTS`
- `TRUSTED_PROXIES`
- `PROXY_ENABLED`
- `LETSENCRYPT_STAGING`

External Core nodes do not need Authentik. User login is handled by Control;
Core nodes authenticate Control-to-Core API calls with HTTPS and
`X-Core-Token`. Configure Authentik only on the node where the Control API is
enabled.

### Registering Servers In Control

Create or edit servers in the Control Admin API/UI with:

| Field | Value |
|---|---|
| Host | Core node domain |
| Port | `443` |
| Endpoint | Core node domain |
| WG Port | `WG_PORT` |
| Public Key | `data.public_key` from `/api/v1/stats` |
| Core Token | that node's `VPN_CORE_TOKEN` |
| Active | `true` |

Fetch a node's WireGuard public key with:

```bash
curl -H "X-Core-Token: $VPN_CORE_TOKEN" https://$DOMAIN/api/v1/stats
```

Use `data.public_key` when creating the server. The Control API also refreshes
the stored public key from `/api/v1/stats` during connection flows.

Validation checklist:

```bash
curl https://$DOMAIN/health
curl -H "X-Core-Token: $VPN_CORE_TOKEN" https://$DOMAIN/api/v1/stats
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
| `VPN_CORE_HOST_PORT` | `8085` | Host loopback port used by host nginx to reach `VPN_CORE_PORT` |
| `VPN_CORE_TOKEN` | *(empty)* | Shared secret for `X-Core-Token` header |
| `WG_INTERFACE` | `wg0` | WireGuard interface name |
| `WG_PORT` | `51820` | WireGuard UDP listen port |
| `WG_SUBNET` | `10.8.0.0/16` | IP pool subnet |
| `WG_CONFIG_DIR` | `/etc/wireguard` | Config persistence directory |
| `WG_ENDPOINT` | *(empty)* | Public IP/hostname for peer configs |

### PostgreSQL and Redis

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_USER` | `midori` | PostgreSQL user used when `DATABASE_URL` is not set |
| `POSTGRES_PASSWORD` | *(empty)* | PostgreSQL password used by both Docker and `vpn-core` |
| `POSTGRES_HOST` | `postgres` | PostgreSQL host used when `DATABASE_URL` is not set |
| `POSTGRES_PORT` | `5432` | PostgreSQL port used when `DATABASE_URL` is not set |
| `POSTGRES_DB` | `midori_vpn` | PostgreSQL database name |
| `POSTGRES_SSLMODE` | `disable` | PostgreSQL SSL mode used when `DATABASE_URL` is not set |
| `DATABASE_URL` | *(derived)* | Optional PostgreSQL connection string override |
| `REDIS_PASSWORD` | *(empty)* | Redis password used by both Docker and `vpn-core` |
| `REDIS_HOST` | `redis` | Redis host used when `REDIS_URL` is not set |
| `REDIS_PORT` | `6379` | Redis port used when `REDIS_URL` is not set |
| `REDIS_DB` | `0` | Redis DB used when `REDIS_URL` is not set |
| `REDIS_URL` | *(derived)* | Optional Redis connection string override |

### Control API (optional — enables login and user management)

| Variable | Default | Description |
|---|---|---|
| `AUTHENTIK_ISSUER` | *(empty)* | OIDC issuer URL |
| `AUTHENTIK_CLIENT_ID` | *(empty)* | Authentik OAuth2 client ID |
| `AUTHENTIK_CLIENT_SECRET` | *(empty)* | Authentik OAuth2 client secret |
| `AUTHENTIK_JWKS_URL` | *(auto from issuer)* | JWKS endpoint URL |

### Security & Limits

| Variable | Default | Description |
|---|---|---|
| `CORS_ALLOWED_ORIGINS` | *(env)* | Comma-separated allowed origins; include the desktop `API_URL` origin and, during legacy rollout, `https://app.astian.org` |
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
- `Auth`, `Control API`, `Admin API`, and `WebSocket` are available only when `AUTHENTIK_CLIENT_ID` is configured and the database is reachable.

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

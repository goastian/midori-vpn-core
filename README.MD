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
# Edit .env — set VPN_CORE_TOKEN, WG_ENDPOINT, AUTHENTIK_CLIENT_ID

# Development (builds from source, includes PostgreSQL + Redis)
docker compose -f docker-compose-dev.yml up --build

# Production (pre-built image)
docker compose up
```

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
| `AUTHENTIK_JWKS_URL` | *(auto from issuer)* | JWKS endpoint URL |

### Security & Limits

| Variable | Default | Description |
|---|---|---|
| `CORS_ALLOWED_ORIGINS` | `https://*.astian.org,...` | Comma-separated allowed origins |
| `RATE_LIMIT_RPS` | `20` | Requests per second per IP (0 = disabled) |
| `RATE_LIMIT_BURST` | `40` | Burst size for rate limiter |
| `MAX_DEVICES_PER_USER` | `5` | Max active VPN connections per user (0 = unlimited) |
| `CORE_TLS_SKIP_VERIFY` | `false` | Skip TLS verification for core-to-core comms |
| `CORE_ALLOW_INSECURE_HTTP` | `false` | Allow HTTP (no TLS) for core-to-core comms in local/testing |

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
# Astian VPN Core

WireGuard VPN management daemon + control panel API written in **Go**, with a **Vue 3** frontend.

## Architecture

```
cmd/vpn-core/main.go        → entrypoint (WireGuard + Control API)
internal/
  api/                       → chi router (orchestrates core + control), shared response helpers
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
web/                         → Vue 3 + TypeScript frontend (panel de control)
```

## Components

### VPN Core API
Low-level WireGuard peer management. Protected by shared secret (`X-Core-Token`).

### Control API
User-facing API for managing VPN connections, servers and audit logs. Protected by JWT tokens from Authentik. Enabled automatically when `DATABASE_URL` and `AUTHENTIK_CLIENT_ID` are set.

### Control Frontend (`web/`)
Vue 3 + TypeScript SPA with OAuth2/OIDC login flow (PKCE) against `accounts.astian.org`.

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
| `AUTHENTIK_ISSUER` | `https://accounts.astian.org/application/o/midorivpn` | OIDC issuer URL |
| `AUTHENTIK_CLIENT_ID` | *(empty)* | Authentik OAuth2 client ID |
| `AUTHENTIK_JWKS_URL` | *(auto from issuer)* | JWKS endpoint URL |

## API Endpoints

### Core API (`X-Core-Token` protected)

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Healthcheck (no auth) |
| `POST` | `/api/v1/peers` | Add peer |
| `DELETE` | `/api/v1/peers/:pubkey` | Remove peer |
| `PUT` | `/api/v1/peers/:pubkey` | Update peer |
| `GET` | `/api/v1/peers/:pubkey/stats` | Peer stats |
| `GET` | `/api/v1/peers` | List all peers |
| `POST` | `/api/v1/keypair` | Generate keypair |
| `GET` | `/api/v1/stats` | Server stats |

### Control API (JWT Bearer protected)

| Method | Path | Description |
|---|---|---|
| `GET` | `/auth/config` | OIDC configuration for frontend |
| `POST` | `/auth/callback` | Exchange auth code for tokens |
| `GET` | `/api/v1/control/me` | Current user profile |
| `GET` | `/api/v1/control/servers` | List active VPN servers |
| `POST` | `/api/v1/control/servers` | Create server (admin) |
| `DELETE` | `/api/v1/control/servers/:id` | Delete server (admin) |
| `GET` | `/api/v1/control/peers` | List my VPN connections |
| `POST` | `/api/v1/control/peers` | Connect to a server |
| `DELETE` | `/api/v1/control/peers/:id` | Disconnect from a server |
| `GET` | `/api/v1/control/audit` | My audit logs |

## License

See [LICENSE](LICENSE) file.
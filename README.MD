# Astian VPN Core

WireGuard VPN management daemon written in **Go** with a REST API.

## Architecture

```
cmd/vpn-core/main.go      → entrypoint
internal/
  api/                     → chi router, handlers, middleware, responses
  config/                  → environment-based configuration
  crypto/                  → Curve25519 keypair generation
  ippool/                  → automatic IP allocation in 10.8.0.0/16
  wg/                      → WireGuard manager (wgctrl + netlink)
```

## Requirements

- **Docker** (recommended) — builds and runs everything in containers
- Or: **Go 1.22+** and a Linux host with WireGuard kernel module

## Quick Start (Docker)

```bash
cp .env.default .env
# Edit .env — set VPN_CORE_TOKEN and WG_ENDPOINT

# Development (builds from source)
docker compose -f docker-compose-dev.yml up --build

# Production (pre-built image)
docker compose up
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `VPN_CORE_PORT` | `8080` | HTTP API listen port |
| `VPN_CORE_TOKEN` | *(empty)* | Shared secret for `X-Core-Token` header |
| `WG_INTERFACE` | `wg0` | WireGuard interface name |
| `WG_PORT` | `51820` | WireGuard UDP listen port |
| `WG_SUBNET` | `10.8.0.0/16` | IP pool subnet |
| `WG_CONFIG_DIR` | `/etc/wireguard` | Config persistence directory |
| `WG_ENDPOINT` | *(empty)* | Public IP/hostname for peer configs |

## API Endpoints

All `/api/v1/*` routes require header: `X-Core-Token: <your-token>`

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Healthcheck (no auth) |
| `POST` | `/api/v1/peers` | Add peer `{"public_key":"...","keepalive":25}` |
| `DELETE` | `/api/v1/peers/:pubkey` | Remove peer |
| `PUT` | `/api/v1/peers/:pubkey` | Update peer `{"keepalive":30}` |
| `GET` | `/api/v1/peers/:pubkey/stats` | Peer stats (tx/rx, handshake) |
| `GET` | `/api/v1/peers` | List all peers |
| `POST` | `/api/v1/keypair` | Generate Curve25519 keypair |
| `GET` | `/api/v1/stats` | Server-wide stats |

## Build Locally (Linux only)

```bash
go build -o vpn-core ./cmd/vpn-core
sudo WG_INTERFACE=wg0 VPN_CORE_TOKEN=secret ./vpn-core
```

## Integration Test on VPS

```bash
# 1. Deploy with docker compose
ssh root@your-vps
git clone <repo> && cd midori-vpn-core
cp .env.default .env && vim .env
docker compose -f docker-compose-dev.yml up --build -d

# 2. Health check
curl http://localhost:8080/health

# 3. Generate keypair
curl -H "X-Core-Token: your-token" -X POST http://localhost:8080/api/v1/keypair

# 4. Add peer
curl -H "X-Core-Token: your-token" -H "Content-Type: application/json" \
  -X POST http://localhost:8080/api/v1/peers \
  -d '{"public_key":"<client-pubkey>","keepalive":25}'

# 5. Check stats
curl -H "X-Core-Token: your-token" http://localhost:8080/api/v1/stats
```

## License

See [LICENSE](LICENSE) file.
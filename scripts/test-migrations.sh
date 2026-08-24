#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-docker.io/library/postgres:18-alpine}"
container="midori-migration-test-$$"

cleanup() {
  podman rm -f "${container}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

podman run -d --name "${container}" \
  -e POSTGRES_USER=midori \
  -e POSTGRES_PASSWORD=migration-test-only \
  -e POSTGRES_DB=midori_vpn \
  -v "${ROOT_DIR}/internal/db/migrations:/migrations:ro,Z" \
  "${POSTGRES_IMAGE}" >/dev/null

for _ in {1..60}; do
  if podman exec "${container}" pg_isready -U midori -d midori_vpn >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
podman exec "${container}" pg_isready -U midori -d midori_vpn >/dev/null

podman exec "${container}" sh -ceu '
  for file in /migrations/*.up.sql; do
    psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -f "$file" >/dev/null
  done
'

remaining="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT count(*) FROM information_schema.columns WHERE table_name = 'vpn_servers' AND column_name IN ('proxy_port','proxy_scheme','wss_tunnel_enabled','wss_host','wss_port')")"
[ "${remaining}" = "0" ] || { printf 'error: migration 9 left %s retired columns\n' "${remaining}" >&2; exit 1; }

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000009_remove_legacy_transport_columns.down.sql >/dev/null
restored="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT count(*) FROM information_schema.columns WHERE table_name = 'vpn_servers' AND column_name IN ('proxy_port','proxy_scheme','wss_tunnel_enabled','wss_host','wss_port')")"
[ "${restored}" = "5" ] || { printf 'error: migration 9 rollback restored %s of 5 columns\n' "${restored}" >&2; exit 1; }

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000009_remove_legacy_transport_columns.up.sql >/dev/null

printf 'Migration chain 1-9 and migration 9 rollback verified on PostgreSQL 18.\n'

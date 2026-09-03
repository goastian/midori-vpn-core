#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================================================================
# Midori VPN — Podman Pod Production & Staging Deployment Script
# ==============================================================================

POD_NAME="midori-vpn-pod"
ENV_FILE="${ENV_FILE:-.env}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_value() {
  local name="$1"
  [ -n "${!name:-}" ] || die "missing required environment variable: ${name}"
}

validate_secret_fingerprints() {
  local entry
  local -a entries
  [[ -n "${NODE_SECRET_FINGERPRINTS:-}" ]] || return 0
  IFS=',' read -ra entries <<< "${NODE_SECRET_FINGERPRINTS}"
  for entry in "${entries[@]}"; do
    [[ "${entry}" =~ ^[a-z0-9][a-z0-9._-]{0,63}=[a-f0-9]{64}$ ]] || \
      die "NODE_SECRET_FINGERPRINTS must contain name=64-lowercase-hex entries"
  done
}

wait_healthy() {
  local container="$1"
  local state
  for _ in {1..60}; do
    state="$(podman inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container}")"
    case "${state}" in
      healthy|running) return 0 ;;
      unhealthy|exited|stopped) die "container ${container} entered state ${state}" ;;
    esac
    sleep 1
  done
  die "container ${container} did not become healthy within 60 seconds"
}

if [ "$(id -u)" -eq 0 ]; then
  die "run this deployment as the dedicated unprivileged Podman user"
fi

[ -f "${ENV_FILE}" ] || die "environment file not found: ${ENV_FILE}"

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

if [ "${DEPLOYMENT_PROFILE:-}" != "principal" ]; then
  die "DEPLOYMENT_PROFILE must be principal"
fi

require_value CORE_NODE_NAME
[[ "${CORE_NODE_NAME}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "CORE_NODE_NAME must be a lowercase DNS label"

for required_var in \
  CORE_IMAGE CONTROL_IMAGE POSTGRES_IMAGE PGBOUNCER_IMAGE REDIS_IMAGE \
  VPN_CORE_PORT VPN_CORE_HOST_PORT CONTROL_CONTAINER_PORT CONTROL_HOST_PORT \
  WG_PORT WG_INTERFACE WG_SUBNET WG_CONFIG_DIR WG_ENDPOINT VPN_DNS \
  POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB REDIS_PASSWORD \
  CONTROL_NODE_ID CONTROL_NODE_PRIVATE_KEY NODE_AUTHORIZED_KEYS NODE_AUTH_REDIS_URL CREDENTIAL_SIGNING_SECRET CONTROL_DATA_ENCRYPTION_KEY \
  APP_ENV PUBLIC_BASE_URL CORS_ALLOWED_ORIGINS EXTENSION_CALLBACK_PATH \
  AUTHENTIK_ISSUER AUTHENTIK_CLIENT_ID \
  OAUTH_ALLOWED_REDIRECT_URIS CONTROL_OAUTH_REDIRECT_URI \
  CORE_TLS_SKIP_VERIFY CORE_ALLOW_INSECURE_HTTP \
  RATE_LIMIT_RPS RATE_LIMIT_BURST CONNECT_RATE_LIMIT_RPS CONNECT_RATE_LIMIT_BURST \
  MAX_DEVICES_PER_USER PROXY_ENABLED PROXY_PORT \
  PROXY_MAX_CONNS_PER_USER PROXY_TLS_ENABLED PROXY_TLS_TERMINATED_BY_NGINX \
  WSS_TUNNEL_ENABLED WSS_TUNNEL_MAX_CLIENTS \
  MASQUE_ENABLED MASQUE_PORT MASQUE_MAX_CLIENTS \
  WS_MAX_GLOBAL WS_MAX_FREE WS_MAX_BASIC WS_MAX_MEDIUM WS_MAX_PRO WS_MAX_ADMIN; do
  require_value "${required_var}"
done

node_identity_configured=false
for node_identity_var in NODE_CONTROL_URL CORE_NODE_ID CORE_NODE_STATE_DIR CORE_NODE_STATE_HOST_DIR CORE_NODE_ENROLLMENT_TOKEN_FILE CORE_NODE_MAX_PEERS; do
  if [[ -n "${!node_identity_var:-}" ]]; then
    node_identity_configured=true
  fi
done
if [[ "${node_identity_configured}" == "true" ]]; then
  for node_identity_var in NODE_CONTROL_URL CORE_NODE_ID CORE_NODE_STATE_DIR CORE_NODE_STATE_HOST_DIR CORE_NODE_ENROLLMENT_TOKEN_FILE CORE_NODE_MAX_PEERS; do
    require_value "${node_identity_var}"
  done
  [[ "${NODE_CONTROL_URL}" == https://* ]] || die "NODE_CONTROL_URL must be an HTTPS origin"
  [[ "${CORE_NODE_ID}" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]] || die "CORE_NODE_ID must be a UUID"
  [[ "${CORE_NODE_STATE_DIR}" == /* && "${CORE_NODE_STATE_HOST_DIR}" == /* ]] || die "Core node state directories must be absolute"
  [[ "${CORE_NODE_ENROLLMENT_TOKEN_FILE}" == "${CORE_NODE_STATE_DIR}/enrollment-token" ]] || die "CORE_NODE_ENROLLMENT_TOKEN_FILE must be the enrollment-token file inside CORE_NODE_STATE_DIR"
  [[ -d "${CORE_NODE_STATE_HOST_DIR}" && ! -L "${CORE_NODE_STATE_HOST_DIR}" ]] || die "CORE_NODE_STATE_HOST_DIR must be a real directory"
  [[ "$(stat -c '%a' "${CORE_NODE_STATE_HOST_DIR}")" == "700" ]] || die "CORE_NODE_STATE_HOST_DIR must have mode 0700"
  if [[ -e "${CORE_NODE_STATE_HOST_DIR}/enrollment-token" ]]; then
    [[ -f "${CORE_NODE_STATE_HOST_DIR}/enrollment-token" && ! -L "${CORE_NODE_STATE_HOST_DIR}/enrollment-token" ]] || die "enrollment-token must be a regular file"
    [[ "$(stat -c '%a' "${CORE_NODE_STATE_HOST_DIR}/enrollment-token")" == "600" ]] || die "enrollment-token must have mode 0600"
  fi
  [[ "${CORE_NODE_MAX_PEERS}" =~ ^[1-9][0-9]*$ ]] || die "CORE_NODE_MAX_PEERS must be positive"
  (( CORE_NODE_MAX_PEERS <= 65536 )) || die "CORE_NODE_MAX_PEERS must not exceed 65536"
  validate_secret_fingerprints
fi

case "${PROXY_ENABLED}" in
  true|false) ;;
  *) die "PROXY_ENABLED must be true or false" ;;
esac

if [ "${WSS_TUNNEL_ENABLED}" = "true" ]; then
  require_value WSS_TUNNEL_SERVER_ID
fi

if [ "${MASQUE_ENABLED}" = "true" ]; then
  for masque_var in MASQUE_TLS_CERT MASQUE_TLS_KEY MASQUE_URI_TEMPLATE MASQUE_SERVER_ID; do
    require_value "${masque_var}"
  done
fi

if [ "${PROXY_ENABLED}" = "true" ]; then
  require_value PROXY_HOST_PORT
fi

if [ "${PROXY_ENABLED}" = "true" ] && [ "${PROXY_TLS_ENABLED}" != "true" ] && [ "${PROXY_TLS_TERMINATED_BY_NGINX}" != "true" ]; then
  die "the enabled proxy requires direct TLS or TLS termination by the host Nginx"
fi

echo "🚀 Iniciando despliegue de Midori VPN Pod (${POD_NAME})..."

if podman pod exists "${POD_NAME}" 2>/dev/null; then
  echo "🧹 Deteniendo y eliminando pod anterior..."
  podman pod rm -f "${POD_NAME}"
fi

echo "📦 Creando Podman Pod '${POD_NAME}'..."
pod_args=(
  pod create
  --name "${POD_NAME}"
  -p "${WG_PORT}:${WG_PORT}/udp"
  -p "127.0.0.1:${VPN_CORE_HOST_PORT}:${VPN_CORE_PORT}/tcp"
  -p "127.0.0.1:${CONTROL_HOST_PORT}:${CONTROL_CONTAINER_PORT}/tcp"
)
if [ "${PROXY_ENABLED}" = "true" ]; then
  pod_args+=(-p "127.0.0.1:${PROXY_HOST_PORT}:${PROXY_PORT}/tcp")
fi
if [ "${MASQUE_ENABLED}" = "true" ]; then
  pod_args+=(-p "${MASQUE_PORT}:${MASQUE_PORT}/udp")
fi
podman "${pod_args[@]}"

echo "🐘 Iniciando midori-postgres..."
podman run -d \
  --pod "${POD_NAME}" \
  --name midori-postgres \
  --restart always \
  -e POSTGRES_USER="${POSTGRES_USER}" \
  -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  -v midori-pgdata-v18:/var/lib/postgresql:Z \
  --health-cmd 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  --health-interval 2s \
  --health-timeout 3s \
  --health-retries 30 \
  "${POSTGRES_IMAGE}"

echo "⚡ Iniciando midori-redis..."
podman run -d \
  --pod "${POD_NAME}" \
  --name midori-redis \
  --restart always \
  -e REDIS_PASSWORD="${REDIS_PASSWORD}" \
  -v midori-redisdata:/data:Z \
  --health-cmd 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli ping | grep -qx PONG' \
  --health-interval 2s \
  --health-timeout 3s \
  --health-retries 30 \
  "${REDIS_IMAGE}" sh -ceu 'exec redis-server --requirepass "$REDIS_PASSWORD"'

echo "⏳ Esperando PostgreSQL y Redis..."
wait_healthy midori-postgres
wait_healthy midori-redis

echo "🔗 Iniciando PgBouncer..."
podman run -d \
  --pod "${POD_NAME}" \
  --name midori-pgbouncer \
  --restart always \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --tmpfs /run/pgbouncer:rw,noexec,nosuid,nodev,size=4m,mode=1733 \
  -e POSTGRES_HOST=127.0.0.1 \
  -e POSTGRES_PORT=5432 \
  -e POSTGRES_USER="${POSTGRES_USER}" \
  -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  --health-cmd 'PGPASSWORD="$POSTGRES_PASSWORD" pg_isready -h 127.0.0.1 -p 6432 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  --health-interval 2s \
  --health-timeout 3s \
  --health-retries 30 \
  "${PGBOUNCER_IMAGE}"

wait_healthy midori-pgbouncer

echo "🛡️ Iniciando midori-vpn-core..."
core_volume_args=(
  -v wg-config:/etc/wireguard:Z
)
if [[ "${node_identity_configured}" == "true" ]]; then
  core_volume_args+=(-v "${CORE_NODE_STATE_HOST_DIR}:${CORE_NODE_STATE_DIR}:Z")
fi
if [ "${MASQUE_ENABLED}" = "true" ]; then
  core_volume_args+=(
    -v /etc/letsencrypt/live:/etc/letsencrypt/live:ro
    -v /etc/letsencrypt/archive:/etc/letsencrypt/archive:ro
  )
fi
podman run -d \
  --pod "${POD_NAME}" \
  --name midori-vpn-core \
  --restart always \
  --cap-drop=ALL \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --env-file "${ENV_FILE}" \
  -e DATABASE_URL= \
  -e POSTGRES_HOST=127.0.0.1 \
  -e POSTGRES_PORT=6432 \
  -e REDIS_HOST=127.0.0.1 \
  "${core_volume_args[@]}" \
  --health-cmd 'wget -q -O /dev/null "http://127.0.0.1:$VPN_CORE_PORT/readyz"' \
  --health-interval 5s \
  --health-timeout 4s \
  --health-retries 24 \
  "${CORE_IMAGE}"

wait_healthy midori-vpn-core

echo "🖥️ Iniciando midori-vpn-control..."
podman run -d \
  --pod "${POD_NAME}" \
  --name midori-vpn-control \
  --restart always \
  --env-file "${ENV_FILE}" \
  --health-cmd 'wget -q -O /dev/null "http://127.0.0.1:$CONTROL_CONTAINER_PORT/"' \
  --health-interval 5s \
  --health-timeout 4s \
  --health-retries 24 \
  "${CONTROL_IMAGE}"

wait_healthy midori-vpn-control

echo "✅ ¡Despliegue del Podman Pod completado exitosamente!"
podman pod ps --filter "name=${POD_NAME}"

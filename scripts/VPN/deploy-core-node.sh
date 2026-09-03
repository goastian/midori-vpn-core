#!/usr/bin/env bash
set -Eeuo pipefail

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

ENV_FILE="${ENV_FILE:-.env}"

require_value() {
  local name="$1"
  [[ -n "${!name:-}" ]] || die "missing required environment variable: ${name}"
}

require_empty() {
  local name="$1"
  [[ -z "${!name:-}" ]] || die "${name} must be empty on a regional Core node"
}

require_bool() {
  local name="$1"
  case "${!name:-}" in
    true|false) ;;
    *) die "${name} must be true or false" ;;
  esac
}

require_port() {
  local name="$1" value="${!1:-}"
  [[ "${value}" =~ ^[0-9]+$ ]] || die "${name} must be an integer port"
  (( value >= 1 && value <= 65535 )) || die "${name} must be between 1 and 65535"
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
  local container="$1" state
  for _ in {1..60}; do
    state="$(podman inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container}")"
    case "${state}" in
      healthy) return 0 ;;
      unhealthy|exited|stopped) die "container ${container} entered state ${state}" ;;
    esac
    sleep 1
  done
  die "container ${container} did not become healthy within 60 seconds"
}

[[ "$(id -u)" -ne 0 ]] || die "run as the dedicated unprivileged Podman user"
[[ -f "${ENV_FILE}" ]] || die "environment file not found: ${ENV_FILE}"

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

[[ "${DEPLOYMENT_PROFILE:-}" == "core-node" ]] || die "DEPLOYMENT_PROFILE must be core-node"

for name in CORE_NODE_NAME CORE_IMAGE REDIS_IMAGE REDIS_PASSWORD \
  VPN_CORE_PORT VPN_CORE_HOST_PORT WG_PORT WG_INTERFACE WG_SUBNET WG_CONFIG_DIR \
  WG_ENDPOINT VPN_DNS NODE_AUTHORIZED_KEYS NODE_AUTH_REDIS_URL APP_ENV \
  PUBLIC_BASE_URL CORS_ALLOWED_ORIGINS EXTENSION_CALLBACK_PATH \
  CORE_TLS_SKIP_VERIFY CORE_ALLOW_INSECURE_HTTP RATE_LIMIT_RPS RATE_LIMIT_BURST \
  CONNECT_RATE_LIMIT_RPS CONNECT_RATE_LIMIT_BURST MAX_DEVICES_PER_USER \
  PROXY_ENABLED WSS_TUNNEL_ENABLED MASQUE_ENABLED WS_MAX_GLOBAL WS_MAX_FREE \
  WS_MAX_BASIC WS_MAX_MEDIUM WS_MAX_PRO WS_MAX_ADMIN NODE_CONTROL_URL \
  CORE_NODE_ID CORE_NODE_STATE_DIR CORE_NODE_STATE_HOST_DIR \
  CORE_NODE_ENROLLMENT_TOKEN_FILE CORE_NODE_MAX_PEERS; do
  require_value "${name}"
done

for name in CONTROL_NODE_ID CONTROL_NODE_PRIVATE_KEY CONTROL_DATA_ENCRYPTION_KEY DATABASE_URL POSTGRES_USER \
  POSTGRES_PASSWORD POSTGRES_HOST POSTGRES_PORT POSTGRES_DB POSTGRES_SSLMODE \
  AUTHENTIK_ISSUER AUTHENTIK_CLIENT_ID AUTHENTIK_CLIENT_SECRET \
  AUTHENTIK_JWKS_URL AUTHENTIK_INTROSPECTION_URL OAUTH_ALLOWED_REDIRECT_URIS \
  CONTROL_OAUTH_REDIRECT_URI VPN_CLIENT_CA_KEY CONTROL_IMAGE CONTROL_HOST_PORT \
  CONTROL_CONTAINER_PORT; do
  require_empty "${name}"
done

[[ "${CORE_NODE_NAME}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "CORE_NODE_NAME must be a lowercase DNS label"
[[ "${APP_ENV}" == "production" ]] || die "regional Core nodes require APP_ENV=production"
[[ "${NODE_AUTH_REDIS_URL}" == redis://* || "${NODE_AUTH_REDIS_URL}" == rediss://* ]] || die "NODE_AUTH_REDIS_URL must be a Redis URL"
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
require_port VPN_CORE_PORT
require_port VPN_CORE_HOST_PORT
require_port WG_PORT
require_bool CORE_TLS_SKIP_VERIFY
require_bool CORE_ALLOW_INSECURE_HTTP
require_bool PROXY_ENABLED
require_bool WSS_TUNNEL_ENABLED
require_bool MASQUE_ENABLED

if [[ "${PROXY_ENABLED}" == "true" ]]; then
  require_value PROXY_PORT
  require_value PROXY_HOST_PORT
  require_port PROXY_PORT
  require_port PROXY_HOST_PORT
fi
if [[ "${WSS_TUNNEL_ENABLED}" == "true" ]]; then
  require_value WSS_TUNNEL_SERVER_ID
  require_value CREDENTIAL_SIGNING_SECRET
fi
if [[ "${MASQUE_ENABLED}" == "true" ]]; then
  for name in MASQUE_PORT MASQUE_TLS_CERT MASQUE_TLS_KEY MASQUE_URI_TEMPLATE MASQUE_SERVER_ID MASQUE_MAX_CLIENTS CREDENTIAL_SIGNING_SECRET; do
    require_value "${name}"
  done
  require_port MASQUE_PORT
fi

pod_name="midori-${CORE_NODE_NAME}"
redis_name="${pod_name}-redis"
core_name="${pod_name}-core"

if podman pod exists "${pod_name}"; then
  podman pod rm --force "${pod_name}"
fi

pod_args=(
  pod create --name "${pod_name}"
  --publish "${WG_PORT}:${WG_PORT}/udp"
  --publish "127.0.0.1:${VPN_CORE_HOST_PORT}:${VPN_CORE_PORT}/tcp"
)
if [[ "${PROXY_ENABLED}" == "true" ]]; then
  pod_args+=(--publish "127.0.0.1:${PROXY_HOST_PORT}:${PROXY_PORT}/tcp")
fi
if [[ "${MASQUE_ENABLED}" == "true" ]]; then
  pod_args+=(--publish "${MASQUE_PORT}:${MASQUE_PORT}/udp")
fi
podman "${pod_args[@]}"

podman run --detach \
  --pod "${pod_name}" \
  --name "${redis_name}" \
  --restart always \
  --env REDIS_PASSWORD="${REDIS_PASSWORD}" \
  --volume "${redis_name}-data:/data:Z" \
  --health-cmd 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli ping | grep -qx PONG' \
  --health-interval 2s \
  --health-timeout 3s \
  --health-retries 30 \
  "${REDIS_IMAGE}" sh -ceu 'exec redis-server --requirepass "$REDIS_PASSWORD"'
wait_healthy "${redis_name}"

core_volumes=(
  --volume "${core_name}-wg:${WG_CONFIG_DIR}:Z"
  --volume "${CORE_NODE_STATE_HOST_DIR}:${CORE_NODE_STATE_DIR}:Z"
  --volume /run/midorivpn-health:/run/midorivpn-health:ro
)
if [[ "${MASQUE_ENABLED}" == "true" ]]; then
  core_volumes+=(
    --volume /etc/letsencrypt/live:/etc/letsencrypt/live:ro
    --volume /etc/letsencrypt/archive:/etc/letsencrypt/archive:ro
  )
fi

podman run --detach \
  --pod "${pod_name}" \
  --name "${core_name}" \
  --restart always \
  --cap-drop all \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --env-file "${ENV_FILE}" \
  "${core_volumes[@]}" \
  --health-cmd 'wget -q -O /dev/null "http://127.0.0.1:$VPN_CORE_PORT/readyz"' \
  --health-interval 5s \
  --health-timeout 4s \
  --health-retries 24 \
  "${CORE_IMAGE}"
wait_healthy "${core_name}"

printf 'Regional Core profile is healthy: pod=%s core=%s redis=%s\n' "${pod_name}" "${core_name}" "${redis_name}"
printf 'Register its HTTPS management hostname and transports in Control before setting is_active=true.\n'

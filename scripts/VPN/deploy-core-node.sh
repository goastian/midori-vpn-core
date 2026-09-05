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

require_private_ipv4() {
  local name="$1" value="${!1:-}" octet
  local -a octets
  IFS=. read -ra octets <<< "${value}"
  [[ "${#octets[@]}" -eq 4 ]] || die "${name} must be an explicit RFC1918 or loopback IPv4 address"
  for octet in "${octets[@]}"; do
    if [[ ! "${octet}" =~ ^(0|[1-9][0-9]{0,2})$ ]] || ((10#${octet} > 255)); then
      die "${name} must be an explicit RFC1918 or loopback IPv4 address"
    fi
  done
  case "${octets[0]}.${octets[1]}" in
    10.*|127.*|192.168) return 0 ;;
  esac
  [[ "${octets[0]}" == "172" && "${octets[1]}" -ge 16 && "${octets[1]}" -le 31 ]] || \
    die "${name} must be an explicit RFC1918 or loopback IPv4 address"
}

require_spiffe_uri() {
  local name="$1" value="${!1:-}"
  [[ "${value}" =~ ^spiffe://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(/[A-Za-z0-9._~-]+)+$ ]] || \
    die "${name} must be an absolute spiffe URI without credentials, query or fragment"
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

validate_external_transports() {
  local entry
  local seen=","
  local -a entries
  [[ -n "${NODE_EXTERNAL_TRANSPORTS:-}" ]] || return 0
  IFS=',' read -ra entries <<< "${NODE_EXTERNAL_TRANSPORTS}"
  for entry in "${entries[@]}"; do
    [[ "${entry}" == "openvpn" || "${entry}" == "ikev2" ]] || \
      die "NODE_EXTERNAL_TRANSPORTS accepts only lowercase openvpn and ikev2"
    [[ "${seen}" != *",${entry},"* ]] || die "NODE_EXTERNAL_TRANSPORTS entries must be unique"
    seen+="${entry},"
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
  TRANSPORT_TOKEN_ISSUER TRANSPORT_TOKEN_AUTHORIZED_KEYS TRANSPORT_CLUSTER_ID \
  ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS \
  PUBLIC_BASE_URL CORS_ALLOWED_ORIGINS EXTENSION_CALLBACK_PATH \
  CORE_TLS_SKIP_VERIFY CORE_ALLOW_INSECURE_HTTP RATE_LIMIT_RPS RATE_LIMIT_BURST \
  CONNECT_RATE_LIMIT_RPS CONNECT_RATE_LIMIT_BURST MAX_DEVICES_PER_USER \
  PROXY_ENABLED WSS_TUNNEL_ENABLED MASQUE_ENABLED WS_MAX_GLOBAL WS_MAX_FREE \
  WS_MAX_BASIC WS_MAX_MEDIUM WS_MAX_PRO WS_MAX_ADMIN NODE_CONTROL_URL \
  CORE_NODE_ID CORE_NODE_STATE_DIR CORE_NODE_STATE_HOST_DIR \
  CORE_NODE_ENROLLMENT_TOKEN_FILE CORE_NODE_MAX_PEERS \
  OBSERVABILITY_MTLS_PORT OBSERVABILITY_HOST_BIND OBSERVABILITY_TLS_CERT \
  OBSERVABILITY_TLS_KEY OBSERVABILITY_CLIENT_CA OBSERVABILITY_ALLOWED_CLIENT_URI; do
  require_value "${name}"
done

for name in CONTROL_NODE_ID CONTROL_NODE_PRIVATE_KEY CONTROL_DATA_ENCRYPTION_KEY DATABASE_URL MIGRATION_DATABASE_URL \
  POSTGRES_USER POSTGRES_PASSWORD POSTGRES_ADMIN_USER POSTGRES_ADMIN_PASSWORD POSTGRES_OWNER_ROLE \
  POSTGRES_MIGRATOR_USER POSTGRES_MIGRATOR_PASSWORD POSTGRES_RUNTIME_USER POSTGRES_RUNTIME_PASSWORD \
  POSTGRES_BACKUP_USER POSTGRES_BACKUP_PASSWORD \
  POSTGRES_HOST POSTGRES_PORT POSTGRES_DB POSTGRES_SSLMODE POSTGRES_MIGRATION_HOST \
  POSTGRES_MIGRATION_PORT POSTGRES_MIGRATION_SSLMODE PGBOUNCER_ADMIN_USER PGBOUNCER_ADMIN_PASSWORD \
  AUTHENTIK_ISSUER AUTHENTIK_CLIENT_ID AUTHENTIK_CLIENT_SECRET \
  AUTHENTIK_JWKS_URL AUTHENTIK_INTROSPECTION_URL OAUTH_ALLOWED_REDIRECT_URIS \
  CONTROL_OAUTH_REDIRECT_URI VPN_CLIENT_CA_KEY CONTROL_IMAGE CONTROL_HOST_PORT \
  CONTROL_CONTAINER_PORT CREDENTIAL_SIGNING_SECRET; do
  require_empty "${name}"
done

for name in PROMETHEUS_MTLS_CLIENT_CERT PROMETHEUS_MTLS_CLIENT_KEY; do
  require_empty "${name}"
done

[[ "${CORE_NODE_NAME}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "CORE_NODE_NAME must be a lowercase DNS label"
[[ "${APP_ENV}" == "production" ]] || die "regional Core nodes require APP_ENV=production"
[[ "${ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS}" == "false" ]] || die "regional Core nodes forbid legacy HMAC transport credentials"
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
validate_external_transports
require_port VPN_CORE_PORT
require_port VPN_CORE_HOST_PORT
require_port WG_PORT
require_port OBSERVABILITY_MTLS_PORT
[[ "${OBSERVABILITY_MTLS_PORT}" == "9443" ]] || die "OBSERVABILITY_MTLS_PORT must use fleet-standard port 9443"
require_private_ipv4 OBSERVABILITY_HOST_BIND
require_spiffe_uri OBSERVABILITY_ALLOWED_CLIENT_URI
for observability_file in OBSERVABILITY_TLS_CERT OBSERVABILITY_TLS_KEY OBSERVABILITY_CLIENT_CA; do
  observability_path="${!observability_file}"
  [[ "${observability_path}" = /* && -f "${observability_path}" && ! -L "${observability_path}" ]] || die "${observability_file} must be an absolute regular file"
done
[[ "$(stat -c '%a' "${OBSERVABILITY_TLS_KEY}")" == "600" ]] || die "OBSERVABILITY_TLS_KEY must have mode 0600"
require_bool CORE_TLS_SKIP_VERIFY
require_bool CORE_ALLOW_INSECURE_HTTP
require_bool PROXY_ENABLED
require_bool WSS_TUNNEL_ENABLED
require_bool MASQUE_ENABLED

if [[ "${PROXY_ENABLED}" == "true" ]]; then
  require_value PROXY_PORT
  require_value PROXY_HOST_PORT
  require_value PROXY_SERVER_ID
  require_port PROXY_PORT
  require_port PROXY_HOST_PORT
fi
if [[ "${WSS_TUNNEL_ENABLED}" == "true" ]]; then
  require_value WSS_TUNNEL_SERVER_ID
fi
if [[ "${MASQUE_ENABLED}" == "true" ]]; then
  for name in MASQUE_PORT MASQUE_HOST_PORT MASQUE_TLS_CERT MASQUE_TLS_KEY MASQUE_URI_TEMPLATE MASQUE_SERVER_ID MASQUE_MAX_CLIENTS; do
    require_value "${name}"
  done
  require_port MASQUE_PORT
  require_port MASQUE_HOST_PORT
  (( MASQUE_HOST_PORT >= 1024 )) || die "MASQUE_HOST_PORT must be unprivileged for rootless Podman"
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
  --publish "${OBSERVABILITY_HOST_BIND}:${OBSERVABILITY_MTLS_PORT}:${OBSERVABILITY_MTLS_PORT}/tcp"
)
if [[ "${PROXY_ENABLED}" == "true" ]]; then
  pod_args+=(--publish "127.0.0.1:${PROXY_HOST_PORT}:${PROXY_PORT}/tcp")
fi
if [[ "${MASQUE_ENABLED}" == "true" ]]; then
  pod_args+=(--publish "${MASQUE_HOST_PORT}:${MASQUE_PORT}/udp")
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
  --volume "${OBSERVABILITY_TLS_CERT}:${OBSERVABILITY_TLS_CERT}:ro,z"
  --volume "${OBSERVABILITY_TLS_KEY}:${OBSERVABILITY_TLS_KEY}:ro,z"
  --volume "${OBSERVABILITY_CLIENT_CA}:${OBSERVABILITY_CLIENT_CA}:ro,z"
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

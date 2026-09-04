#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================================================================
# Midori VPN — Podman Pod Production & Staging Deployment Script
# ==============================================================================

POD_NAME="midori-vpn-pod"
ENV_FILE="${ENV_FILE:-.env}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POSTGRES_ROLE_SQL="${SCRIPT_DIR}/../deploy/postgres/configure-roles.sql"
POSTGRES_POLICY_SQL="${SCRIPT_DIR}/../deploy/postgres/check-policy.sql"
POSTGRES_BACKUP_SCRIPT="${SCRIPT_DIR}/backup-postgres.sh"
POSTGRES_RESTORE_SCRIPT="${SCRIPT_DIR}/restore-postgres-backup.sh"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_value() {
  local name="$1"
  [ -n "${!name:-}" ] || die "missing required environment variable: ${name}"
}

require_bool() {
  local name="$1"
  case "${!name:-}" in
    true|false) ;;
    *) die "${name} must be true or false" ;;
  esac
}

require_identifier() {
  local name="$1"
  [[ "${!name:-}" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] || die "${name} must be a simple PostgreSQL identifier"
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
[[ -f "${POSTGRES_ROLE_SQL}" && ! -L "${POSTGRES_ROLE_SQL}" ]] || die "PostgreSQL role policy not found: ${POSTGRES_ROLE_SQL}"
[[ -f "${POSTGRES_POLICY_SQL}" && ! -L "${POSTGRES_POLICY_SQL}" ]] || die "PostgreSQL policy check not found: ${POSTGRES_POLICY_SQL}"
[[ -f "${POSTGRES_BACKUP_SCRIPT}" && ! -L "${POSTGRES_BACKUP_SCRIPT}" ]] || die "PostgreSQL backup script not found: ${POSTGRES_BACKUP_SCRIPT}"
[[ -f "${POSTGRES_RESTORE_SCRIPT}" && ! -L "${POSTGRES_RESTORE_SCRIPT}" ]] || die "PostgreSQL restore script not found: ${POSTGRES_RESTORE_SCRIPT}"

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

core_env_file="$(mktemp "${TMPDIR:-/tmp}/midorivpn-core-env.XXXXXX")"
control_env_file="$(mktemp "${TMPDIR:-/tmp}/midorivpn-control-env.XXXXXX")"
chmod 0600 "${core_env_file}" "${control_env_file}"
cleanup_env_files() {
  rm -f -- "${core_env_file}" "${control_env_file}"
}
trap cleanup_env_files EXIT
awk -F= '$1 !~ /^(POSTGRES_ADMIN_|POSTGRES_OWNER_|POSTGRES_MIGRATOR_|POSTGRES_BACKUP_|POSTGRES_DATA_|PGBOUNCER_ADMIN_|BACKUP_|MIGRATION_DATABASE_URL$|POSTGRES_USER$|POSTGRES_PASSWORD$)/' \
  "${ENV_FILE}" > "${core_env_file}"
awk -F= '$1 !~ /^(POSTGRES_|PGBOUNCER_|DATABASE_URL$|MIGRATION_DATABASE_URL$|DATABASE_POOL_)/' \
  "${ENV_FILE}" > "${control_env_file}"

if [ "${DEPLOYMENT_PROFILE:-}" != "principal" ]; then
  die "DEPLOYMENT_PROFILE must be principal"
fi

require_value CORE_NODE_NAME
[[ "${CORE_NODE_NAME}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die "CORE_NODE_NAME must be a lowercase DNS label"

for required_var in \
  CORE_IMAGE CONTROL_IMAGE POSTGRES_IMAGE PGBOUNCER_IMAGE REDIS_IMAGE \
  VPN_CORE_PORT VPN_CORE_HOST_PORT CONTROL_CONTAINER_PORT CONTROL_HOST_PORT \
  WG_PORT WG_INTERFACE WG_SUBNET WG_CONFIG_DIR WG_ENDPOINT VPN_DNS \
  POSTGRES_ADMIN_USER POSTGRES_ADMIN_PASSWORD POSTGRES_OWNER_ROLE \
  POSTGRES_MIGRATOR_USER POSTGRES_MIGRATOR_PASSWORD \
  POSTGRES_RUNTIME_USER POSTGRES_RUNTIME_PASSWORD POSTGRES_DB \
  POSTGRES_BACKUP_USER POSTGRES_BACKUP_PASSWORD \
  POSTGRES_DATA_AT_REST_ENCRYPTED POSTGRES_BACKUP_DIR BACKUP_GPG_RECIPIENT \
  PGBOUNCER_ADMIN_USER PGBOUNCER_ADMIN_PASSWORD \
  PGBOUNCER_MAX_CLIENT_CONN PGBOUNCER_DEFAULT_POOL_SIZE PGBOUNCER_MIN_POOL_SIZE \
  PGBOUNCER_RESERVE_POOL_SIZE PGBOUNCER_MAX_DB_CONNECTIONS \
  DATABASE_POOL_MAX_CONNS DATABASE_POOL_MIN_CONNS REDIS_PASSWORD \
  CONTROL_NODE_ID CONTROL_NODE_PRIVATE_KEY NODE_AUTHORIZED_KEYS NODE_AUTH_REDIS_URL CONTROL_DATA_ENCRYPTION_KEY \
  TRANSPORT_TOKEN_ISSUER TRANSPORT_TOKEN_AUTHORIZED_KEYS ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS \
  APP_ENV PUBLIC_BASE_URL CORS_ALLOWED_ORIGINS EXTENSION_CALLBACK_PATH \
  AUTHENTIK_ISSUER AUTHENTIK_CLIENT_ID \
  OAUTH_ALLOWED_REDIRECT_URIS CONTROL_OAUTH_REDIRECT_URI \
  CORE_TLS_SKIP_VERIFY CORE_ALLOW_INSECURE_HTTP \
  RATE_LIMIT_RPS RATE_LIMIT_BURST CONNECT_RATE_LIMIT_RPS CONNECT_RATE_LIMIT_BURST \
  MAX_DEVICES_PER_USER PROXY_ENABLED PROXY_PORT \
  PROXY_MAX_CONNS_PER_USER PROXY_TLS_ENABLED PROXY_TLS_TERMINATED_BY_NGINX \
  WSS_TUNNEL_ENABLED WSS_TUNNEL_MAX_CLIENTS \
  MASQUE_ENABLED MASQUE_PORT MASQUE_MAX_CLIENTS \
  OBSERVABILITY_NETWORK OBSERVABILITY_MTLS_PORT OBSERVABILITY_TLS_CERT \
  OBSERVABILITY_TLS_KEY OBSERVABILITY_CLIENT_CA OBSERVABILITY_ALLOWED_CLIENT_URI \
  WS_MAX_GLOBAL WS_MAX_FREE WS_MAX_BASIC WS_MAX_MEDIUM WS_MAX_PRO WS_MAX_ADMIN; do
  require_value "${required_var}"
done

for postgres_identifier in POSTGRES_ADMIN_USER POSTGRES_OWNER_ROLE POSTGRES_MIGRATOR_USER POSTGRES_RUNTIME_USER POSTGRES_BACKUP_USER POSTGRES_DB PGBOUNCER_ADMIN_USER; do
  require_identifier "${postgres_identifier}"
done
[[ "${POSTGRES_OWNER_ROLE}" != "${POSTGRES_MIGRATOR_USER}" ]] || die "POSTGRES_OWNER_ROLE and POSTGRES_MIGRATOR_USER must differ"
[[ "${POSTGRES_OWNER_ROLE}" != "${POSTGRES_RUNTIME_USER}" ]] || die "POSTGRES_OWNER_ROLE and POSTGRES_RUNTIME_USER must differ"
[[ "${POSTGRES_MIGRATOR_USER}" != "${POSTGRES_RUNTIME_USER}" ]] || die "POSTGRES_MIGRATOR_USER and POSTGRES_RUNTIME_USER must differ"
[[ "${POSTGRES_BACKUP_USER}" != "${POSTGRES_RUNTIME_USER}" && "${POSTGRES_BACKUP_USER}" != "${POSTGRES_MIGRATOR_USER}" ]] || die "POSTGRES_BACKUP_USER must differ from runtime and migrator roles"
[[ "${PGBOUNCER_ADMIN_USER}" != "${POSTGRES_RUNTIME_USER}" ]] || die "PGBOUNCER_ADMIN_USER and POSTGRES_RUNTIME_USER must differ"
require_bool POSTGRES_DATA_AT_REST_ENCRYPTED
[[ "${POSTGRES_DATA_AT_REST_ENCRYPTED}" == true ]] || die "PostgreSQL data volume must be verified as encrypted at rest before deployment"
[[ "${POSTGRES_BACKUP_DIR}" == /* && -d "${POSTGRES_BACKUP_DIR}" && ! -L "${POSTGRES_BACKUP_DIR}" ]] || die "POSTGRES_BACKUP_DIR must be an absolute real directory"
[[ "$(stat -c '%a' "${POSTGRES_BACKUP_DIR}")" == 700 ]] || die "POSTGRES_BACKUP_DIR must have mode 0700"
[[ "${BACKUP_GPG_RECIPIENT}" =~ ^[A-Fa-f0-9]{40}$ ]] || die "BACKUP_GPG_RECIPIENT must be an exact 40-hex fingerprint"
if [[ ! "${DATABASE_POOL_MAX_CONNS}" =~ ^[1-9][0-9]*$ ]] || (( DATABASE_POOL_MAX_CONNS > 256 )); then
  die "DATABASE_POOL_MAX_CONNS must be between 1 and 256"
fi
if [[ ! "${DATABASE_POOL_MIN_CONNS}" =~ ^[0-9]+$ ]] || (( DATABASE_POOL_MIN_CONNS > DATABASE_POOL_MAX_CONNS )); then
  die "DATABASE_POOL_MIN_CONNS must not exceed DATABASE_POOL_MAX_CONNS"
fi

[[ "${OBSERVABILITY_MTLS_PORT}" == "9443" ]] || die "OBSERVABILITY_MTLS_PORT must use fleet-standard port 9443"
require_spiffe_uri OBSERVABILITY_ALLOWED_CLIENT_URI
[[ "${OBSERVABILITY_NETWORK}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$ ]] || die "OBSERVABILITY_NETWORK must be a Podman network name"
podman network exists "${OBSERVABILITY_NETWORK}" || die "private observability network does not exist: ${OBSERVABILITY_NETWORK}"
for observability_file in OBSERVABILITY_TLS_CERT OBSERVABILITY_TLS_KEY OBSERVABILITY_CLIENT_CA; do
  observability_path="${!observability_file}"
  [[ "${observability_path}" = /* && -f "${observability_path}" && ! -L "${observability_path}" ]] || die "${observability_file} must be an absolute regular file"
done
[[ "$(stat -c '%a' "${OBSERVABILITY_TLS_KEY}")" == "600" ]] || die "OBSERVABILITY_TLS_KEY must have mode 0600"

require_bool ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS
if [[ "${APP_ENV}" == "production" && "${ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS}" != "false" ]]; then
  die "legacy HMAC transport credentials are forbidden in production"
fi
if [[ "${ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS}" == "true" ]]; then
  require_value CREDENTIAL_SIGNING_SECRET
elif [[ -n "${CREDENTIAL_SIGNING_SECRET:-}" ]]; then
  die "CREDENTIAL_SIGNING_SECRET requires explicit development-only opt-in"
fi

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
  validate_external_transports
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
  require_value PROXY_SERVER_ID
fi

if [ "${PROXY_ENABLED}" = "true" ] || [ "${WSS_TUNNEL_ENABLED}" = "true" ] || [ "${MASQUE_ENABLED}" = "true" ]; then
  require_value TRANSPORT_CLUSTER_ID
fi

if [ "${PROXY_ENABLED}" = "true" ] && [ "${PROXY_TLS_ENABLED}" != "true" ] && [ "${PROXY_TLS_TERMINATED_BY_NGINX}" != "true" ]; then
  die "the enabled proxy requires direct TLS or TLS termination by the host Nginx"
fi

echo "🚀 Iniciando despliegue de Midori VPN Pod (${POD_NAME})..."

predeploy_backup_file=""
if podman container exists midori-postgres 2>/dev/null && \
  [[ "$(podman inspect --format '{{.State.Running}}' midori-postgres)" == true ]]; then
  echo "🔒 Creando backup cifrado previo al reinicio..."
  backup_output="$(env \
    POSTGRES_CONTAINER=midori-postgres \
    POSTGRES_DB="${POSTGRES_DB}" \
    POSTGRES_BACKUP_USER="${POSTGRES_ADMIN_USER}" \
    POSTGRES_BACKUP_PASSWORD="${POSTGRES_ADMIN_PASSWORD}" \
    BACKUP_DIR="${POSTGRES_BACKUP_DIR}" \
    BACKUP_GPG_RECIPIENT="${BACKUP_GPG_RECIPIENT}" \
    bash "${POSTGRES_BACKUP_SCRIPT}")"
  printf '%s\n' "${backup_output}"
  predeploy_backup_file="$(awk -F': ' '$1 == "Encrypted PostgreSQL backup created" {print $2; exit}' <<<"${backup_output}")"
  [[ -n "${predeploy_backup_file}" && -f "${predeploy_backup_file}" ]] || die "pre-deployment backup path could not be verified"
fi

if podman pod exists "${POD_NAME}" 2>/dev/null; then
  echo "🧹 Deteniendo y eliminando pod anterior..."
  podman pod rm -f "${POD_NAME}"
fi

echo "📦 Creando Podman Pod '${POD_NAME}'..."
pod_args=(
  pod create
  --name "${POD_NAME}"
  --network "${OBSERVABILITY_NETWORK}"
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
  -e POSTGRES_USER="${POSTGRES_ADMIN_USER}" \
  -e POSTGRES_PASSWORD="${POSTGRES_ADMIN_PASSWORD}" \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  -e POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256 --auth-local=scram-sha-256" \
  -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
  -v midori-pgdata-v18:/var/lib/postgresql:Z \
  --health-cmd 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  --health-interval 2s \
  --health-timeout 3s \
  --health-retries 30 \
  "${POSTGRES_IMAGE}" postgres \
    -c shared_preload_libraries=pg_stat_statements \
    -c password_encryption=scram-sha-256 \
    -c log_connections=off \
    -c log_disconnections=off \
    -c log_statement=none

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

echo "🔐 Aplicando roles y privilegios mínimos de PostgreSQL..."
podman exec -i \
  -e PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  -e POSTGRES_OWNER_ROLE="${POSTGRES_OWNER_ROLE}" \
  -e POSTGRES_MIGRATOR_USER="${POSTGRES_MIGRATOR_USER}" \
  -e POSTGRES_MIGRATOR_PASSWORD="${POSTGRES_MIGRATOR_PASSWORD}" \
  -e POSTGRES_RUNTIME_USER="${POSTGRES_RUNTIME_USER}" \
  -e POSTGRES_RUNTIME_PASSWORD="${POSTGRES_RUNTIME_PASSWORD}" \
  -e POSTGRES_BACKUP_USER="${POSTGRES_BACKUP_USER}" \
  -e POSTGRES_BACKUP_PASSWORD="${POSTGRES_BACKUP_PASSWORD}" \
  midori-postgres psql \
    --username "${POSTGRES_ADMIN_USER}" --dbname postgres --no-psqlrc \
    --set ON_ERROR_STOP=1 < "${POSTGRES_ROLE_SQL}"

podman exec -i \
  -e PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  -e POSTGRES_OWNER_ROLE="${POSTGRES_OWNER_ROLE}" \
  -e POSTGRES_MIGRATOR_USER="${POSTGRES_MIGRATOR_USER}" \
  -e POSTGRES_RUNTIME_USER="${POSTGRES_RUNTIME_USER}" \
  -e POSTGRES_BACKUP_USER="${POSTGRES_BACKUP_USER}" \
  midori-postgres psql \
    --username "${POSTGRES_ADMIN_USER}" --dbname "${POSTGRES_DB}" --no-psqlrc \
    --set ON_ERROR_STOP=1 < "${POSTGRES_POLICY_SQL}"

echo "🧱 Ejecutando migraciones con el rol dedicado..."
podman run --rm \
  --pod "${POD_NAME}" \
  --name midori-db-migrate \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --entrypoint /usr/local/bin/midorivpn-migrate \
  -e POSTGRES_MIGRATOR_USER="${POSTGRES_MIGRATOR_USER}" \
  -e POSTGRES_MIGRATOR_PASSWORD="${POSTGRES_MIGRATOR_PASSWORD}" \
  -e POSTGRES_MIGRATION_HOST=127.0.0.1 \
  -e POSTGRES_MIGRATION_PORT=5432 \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  -e POSTGRES_MIGRATION_SSLMODE=disable \
  "${CORE_IMAGE}"

# Reapply grants to existing objects as a defense-in-depth step for databases
# that predate the default-privilege policy.
podman exec -i \
  -e PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  -e POSTGRES_OWNER_ROLE="${POSTGRES_OWNER_ROLE}" \
  -e POSTGRES_MIGRATOR_USER="${POSTGRES_MIGRATOR_USER}" \
  -e POSTGRES_MIGRATOR_PASSWORD="${POSTGRES_MIGRATOR_PASSWORD}" \
  -e POSTGRES_RUNTIME_USER="${POSTGRES_RUNTIME_USER}" \
  -e POSTGRES_RUNTIME_PASSWORD="${POSTGRES_RUNTIME_PASSWORD}" \
  -e POSTGRES_BACKUP_USER="${POSTGRES_BACKUP_USER}" \
  -e POSTGRES_BACKUP_PASSWORD="${POSTGRES_BACKUP_PASSWORD}" \
  midori-postgres psql \
    --username "${POSTGRES_ADMIN_USER}" --dbname postgres --no-psqlrc \
    --set ON_ERROR_STOP=1 < "${POSTGRES_ROLE_SQL}"

if [[ -n "${predeploy_backup_file}" ]]; then
  restore_database="midorivpn_restore_predeploy_$(date -u +%Y%m%d_%H%M%S)_$$"
  echo "🧪 Probando restore aislado del backup previo..."
  env \
    POSTGRES_CONTAINER=midori-postgres \
    POSTGRES_ADMIN_USER="${POSTGRES_ADMIN_USER}" \
    POSTGRES_ADMIN_PASSWORD="${POSTGRES_ADMIN_PASSWORD}" \
    POSTGRES_OWNER_ROLE="${POSTGRES_OWNER_ROLE}" \
    RESTORE_DATABASE="${restore_database}" \
    BACKUP_FILE="${predeploy_backup_file}" \
    bash "${POSTGRES_RESTORE_SCRIPT}"
  for table_name in users devices peers device_certificates schema_migrations; do
    source_count="$(podman exec -e PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" midori-postgres \
      psql -U "${POSTGRES_ADMIN_USER}" -d "${POSTGRES_DB}" -Atc "SELECT count(*) FROM ${table_name}")"
    restored_count="$(podman exec -e PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" midori-postgres \
      psql -U "${POSTGRES_ADMIN_USER}" -d "${restore_database}" -Atc "SELECT count(*) FROM ${table_name}")"
    [[ "${source_count}" =~ ^[0-9]+$ && "${source_count}" == "${restored_count}" ]] || \
      die "isolated restore count differs for ${table_name}; preserved ${restore_database} for inspection"
  done
  podman exec -e PGPASSWORD="${POSTGRES_ADMIN_PASSWORD}" midori-postgres \
    dropdb --force -U "${POSTGRES_ADMIN_USER}" "${restore_database}"
  echo "✅ Backup previo restaurado y comparado correctamente."
fi

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
  -e POSTGRES_RUNTIME_USER="${POSTGRES_RUNTIME_USER}" \
  -e POSTGRES_RUNTIME_PASSWORD="${POSTGRES_RUNTIME_PASSWORD}" \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  -e PGBOUNCER_ADMIN_USER="${PGBOUNCER_ADMIN_USER}" \
  -e PGBOUNCER_ADMIN_PASSWORD="${PGBOUNCER_ADMIN_PASSWORD}" \
  -e PGBOUNCER_MAX_CLIENT_CONN="${PGBOUNCER_MAX_CLIENT_CONN}" \
  -e PGBOUNCER_DEFAULT_POOL_SIZE="${PGBOUNCER_DEFAULT_POOL_SIZE}" \
  -e PGBOUNCER_MIN_POOL_SIZE="${PGBOUNCER_MIN_POOL_SIZE}" \
  -e PGBOUNCER_RESERVE_POOL_SIZE="${PGBOUNCER_RESERVE_POOL_SIZE}" \
  -e PGBOUNCER_MAX_DB_CONNECTIONS="${PGBOUNCER_MAX_DB_CONNECTIONS}" \
  --health-cmd 'PGPASSWORD="$POSTGRES_RUNTIME_PASSWORD" pg_isready -h 127.0.0.1 -p 6432 -U "$POSTGRES_RUNTIME_USER" -d "$POSTGRES_DB"' \
  --health-interval 2s \
  --health-timeout 3s \
  --health-retries 30 \
  "${PGBOUNCER_IMAGE}"

wait_healthy midori-pgbouncer

echo "🛡️ Iniciando midori-vpn-core..."
core_volume_args=(
  -v wg-config:/etc/wireguard:Z
  -v "${OBSERVABILITY_TLS_CERT}:${OBSERVABILITY_TLS_CERT}:ro,z"
  -v "${OBSERVABILITY_TLS_KEY}:${OBSERVABILITY_TLS_KEY}:ro,z"
  -v "${OBSERVABILITY_CLIENT_CA}:${OBSERVABILITY_CLIENT_CA}:ro,z"
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
  --env-file "${core_env_file}" \
  -e DATABASE_URL= \
  -e POSTGRES_HOST=127.0.0.1 \
  -e POSTGRES_PORT=6432 \
  -e POSTGRES_SSLMODE=disable \
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
  --env-file "${control_env_file}" \
  --health-cmd 'wget -q -O /dev/null "http://127.0.0.1:$CONTROL_CONTAINER_PORT/"' \
  --health-interval 5s \
  --health-timeout 4s \
  --health-retries 24 \
  "${CONTROL_IMAGE}"

wait_healthy midori-vpn-control

echo "✅ ¡Despliegue del Podman Pod completado exitosamente!"
podman pod ps --filter "name=${POD_NAME}"

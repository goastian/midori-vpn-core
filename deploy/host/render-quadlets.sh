#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

env_file=""
output_dir=""
account_home=""
if passwd_entry="$(getent passwd "$(id -u)" 2>/dev/null)"; then
  account_home="$(cut -d: -f6 <<< "${passwd_entry}")"
fi
account_home="${account_home:-${HOME:-}}"
[[ "${account_home}" == /* ]] || host_die "current account has no absolute home directory"
runtime_dir="${account_home}/.config/containers/systemd/midorivpn"

usage() {
  printf 'usage: %s --env-file PATH --output-dir PATH [--runtime-dir ABSOLUTE_PATH]\n' "$0"
}

while (($#)); do
  case "$1" in
    --env-file) env_file="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --runtime-dir) runtime_dir="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

[[ -n "${env_file}" && -n "${output_dir}" ]] || { usage >&2; host_die "--env-file and --output-dir are required"; }
[[ "${runtime_dir}" == /* ]] || host_die "--runtime-dir must be absolute"
host_validate_absolute_path "${runtime_dir}" runtime-dir
[[ ! -e "${output_dir}" ]] || host_die "output path already exists: ${output_dir}"

declare -A cfg=()
host_load_env "${env_file}" cfg
host_require_env cfg DEPLOYMENT_PROFILE
profile="${cfg[DEPLOYMENT_PROFILE]}"
[[ "${profile}" == principal || "${profile}" == core-node ]] || host_die "DEPLOYMENT_PROFILE must be principal or core-node"

for key in CORE_NODE_NAME APP_ENV CORE_IMAGE POD_INFRA_IMAGE REDIS_IMAGE VPN_CORE_PORT VPN_CORE_HOST_PORT WG_PORT WG_INTERFACE WG_SUBNET WG_CONFIG_DIR WG_ENDPOINT VPN_DNS; do
  host_require_env cfg "${key}"
done
[[ "${cfg[CORE_NODE_NAME]}" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || host_die "CORE_NODE_NAME must be a lowercase DNS label"
for key in VPN_CORE_PORT VPN_CORE_HOST_PORT WG_PORT; do
  host_validate_port "${cfg[${key}]}" "${key}" 1024
done
host_validate_absolute_path "${cfg[WG_CONFIG_DIR]}" WG_CONFIG_DIR
for key in CORE_IMAGE POD_INFRA_IMAGE REDIS_IMAGE; do
  host_validate_digest_image "${cfg[${key}]}" "${key}"
done

if [[ "${profile}" == principal ]]; then
  for key in CONTROL_IMAGE POSTGRES_IMAGE PGBOUNCER_IMAGE PROMETHEUS_IMAGE GRAFANA_IMAGE CONTROL_CONTAINER_PORT CONTROL_HOST_PORT PROMETHEUS_HOST_PORT GRAFANA_HOST_PORT POSTGRES_ADMIN_USER POSTGRES_ADMIN_PASSWORD POSTGRES_OWNER_ROLE POSTGRES_MIGRATOR_USER POSTGRES_MIGRATOR_PASSWORD POSTGRES_RUNTIME_USER POSTGRES_RUNTIME_PASSWORD POSTGRES_BACKUP_USER POSTGRES_BACKUP_PASSWORD PGBOUNCER_ADMIN_USER PGBOUNCER_ADMIN_PASSWORD POSTGRES_DB REDIS_PASSWORD OBSERVABILITY_NETWORK OBSERVABILITY_CONFIG_DIR OBSERVABILITY_CLUSTER VPN_CORE_METRICS_TARGET PROMETHEUS_MTLS_CA PROMETHEUS_MTLS_CLIENT_CERT PROMETHEUS_MTLS_CLIENT_KEY GRAFANA_ADMIN_USER GRAFANA_ADMIN_PASSWORD; do
    host_require_env cfg "${key}"
  done
  for key in CONTROL_IMAGE POSTGRES_IMAGE PGBOUNCER_IMAGE PROMETHEUS_IMAGE GRAFANA_IMAGE; do
    host_validate_digest_image "${cfg[${key}]}" "${key}"
  done
  for key in CONTROL_CONTAINER_PORT CONTROL_HOST_PORT PROMETHEUS_HOST_PORT GRAFANA_HOST_PORT OBSERVABILITY_MTLS_PORT; do
    host_validate_port "${cfg[${key}]}" "${key}" 1
  done
  [[ "${cfg[OBSERVABILITY_CLUSTER]}" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || host_die "OBSERVABILITY_CLUSTER must be a lowercase label"
  [[ "${cfg[OBSERVABILITY_NETWORK]}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || host_die "OBSERVABILITY_NETWORK must be a Podman network name"
  [[ "${cfg[VPN_CORE_METRICS_TARGET]}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,62}:[0-9]+$ ]] || host_die "VPN_CORE_METRICS_TARGET must be a DNS name and port"
  [[ "${cfg[GRAFANA_ADMIN_USER]}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || host_die "GRAFANA_ADMIN_USER is invalid"
  ((${#cfg[GRAFANA_ADMIN_PASSWORD]} >= 16)) || host_die "GRAFANA_ADMIN_PASSWORD must contain at least 16 characters"
  for key in PROMETHEUS_MTLS_CA PROMETHEUS_MTLS_CLIENT_CERT PROMETHEUS_MTLS_CLIENT_KEY; do
    host_validate_absolute_path "${cfg[${key}]}" "${key}"
  done
  principal_required=(
    CONTROL_NODE_ID CONTROL_NODE_PRIVATE_KEY NODE_AUTHORIZED_KEYS NODE_AUTH_REDIS_URL
    CONTROL_DATA_ENCRYPTION_KEY TRANSPORT_TOKEN_ISSUER TRANSPORT_TOKEN_AUTHORIZED_KEYS
    ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS APP_ENV PUBLIC_BASE_URL CORS_ALLOWED_ORIGINS
    EXTENSION_CALLBACK_PATH AUTHENTIK_ISSUER AUTHENTIK_CLIENT_ID OAUTH_ALLOWED_REDIRECT_URIS
    CONTROL_OAUTH_REDIRECT_URI CORE_TLS_SKIP_VERIFY CORE_ALLOW_INSECURE_HTTP RATE_LIMIT_RPS
    RATE_LIMIT_BURST CONNECT_RATE_LIMIT_RPS CONNECT_RATE_LIMIT_BURST MAX_DEVICES_PER_USER
    PROXY_ENABLED PROXY_PORT PROXY_MAX_CONNS_PER_USER PROXY_TLS_ENABLED
    PROXY_TLS_TERMINATED_BY_NGINX WSS_TUNNEL_ENABLED WSS_TUNNEL_MAX_CLIENTS
    MASQUE_ENABLED MASQUE_PORT MASQUE_MAX_CLIENTS OBSERVABILITY_MTLS_PORT
    OBSERVABILITY_TLS_CERT OBSERVABILITY_TLS_KEY OBSERVABILITY_CLIENT_CA
    OBSERVABILITY_ALLOWED_CLIENT_URI WS_MAX_GLOBAL WS_MAX_FREE WS_MAX_BASIC WS_MAX_MEDIUM
    WS_MAX_PRO WS_MAX_ADMIN
  )
  for key in "${principal_required[@]}"; do
    host_require_env cfg "${key}"
  done
else
  regional_required=(
    REDIS_PASSWORD NODE_AUTHORIZED_KEYS NODE_AUTH_REDIS_URL TRANSPORT_TOKEN_ISSUER
    TRANSPORT_TOKEN_AUTHORIZED_KEYS TRANSPORT_CLUSTER_ID ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS
    PUBLIC_BASE_URL CORS_ALLOWED_ORIGINS EXTENSION_CALLBACK_PATH CORE_TLS_SKIP_VERIFY
    CORE_ALLOW_INSECURE_HTTP RATE_LIMIT_RPS RATE_LIMIT_BURST CONNECT_RATE_LIMIT_RPS
    CONNECT_RATE_LIMIT_BURST MAX_DEVICES_PER_USER PROXY_ENABLED PROXY_PORT
    PROXY_MAX_CONNS_PER_USER PROXY_TLS_ENABLED PROXY_TLS_TERMINATED_BY_NGINX
    WSS_TUNNEL_ENABLED WSS_TUNNEL_MAX_CLIENTS MASQUE_ENABLED MASQUE_PORT
    MASQUE_MAX_CLIENTS WS_MAX_GLOBAL WS_MAX_FREE WS_MAX_BASIC WS_MAX_MEDIUM WS_MAX_PRO
    WS_MAX_ADMIN NODE_CONTROL_URL CORE_NODE_ID CORE_NODE_STATE_DIR CORE_NODE_STATE_HOST_DIR
    CORE_NODE_ENROLLMENT_TOKEN_FILE CORE_NODE_MAX_PEERS OBSERVABILITY_MTLS_PORT
    OBSERVABILITY_HOST_BIND OBSERVABILITY_TLS_CERT OBSERVABILITY_TLS_KEY
    OBSERVABILITY_CLIENT_CA OBSERVABILITY_ALLOWED_CLIENT_URI
  )
  for key in "${regional_required[@]}"; do
    host_require_env cfg "${key}"
  done
  host_validate_port "${cfg[OBSERVABILITY_MTLS_PORT]}" OBSERVABILITY_MTLS_PORT 1024
  host_validate_absolute_path "${cfg[CORE_NODE_STATE_HOST_DIR]}" CORE_NODE_STATE_HOST_DIR
  host_validate_absolute_path "${cfg[CORE_NODE_STATE_DIR]}" CORE_NODE_STATE_DIR
  [[ "${cfg[APP_ENV]}" == production ]] || host_die "regional Core requires APP_ENV=production"
  [[ "${cfg[ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS]}" == false ]] || host_die "regional Core forbids legacy HMAC transport credentials"
  regional_forbidden=(
    CONTROL_NODE_ID CONTROL_NODE_PRIVATE_KEY CONTROL_DATA_ENCRYPTION_KEY CREDENTIAL_SIGNING_SECRET
    DATABASE_URL MIGRATION_DATABASE_URL POSTGRES_ADMIN_USER POSTGRES_ADMIN_PASSWORD
    POSTGRES_OWNER_ROLE POSTGRES_MIGRATOR_USER POSTGRES_MIGRATOR_PASSWORD
    POSTGRES_RUNTIME_USER POSTGRES_RUNTIME_PASSWORD POSTGRES_BACKUP_USER
    POSTGRES_BACKUP_PASSWORD PGBOUNCER_ADMIN_USER PGBOUNCER_ADMIN_PASSWORD POSTGRES_DB
    AUTHENTIK_ISSUER AUTHENTIK_CLIENT_ID AUTHENTIK_CLIENT_SECRET AUTHENTIK_JWKS_URL
    AUTHENTIK_INTROSPECTION_URL OAUTH_ALLOWED_REDIRECT_URIS CONTROL_OAUTH_REDIRECT_URI
    VPN_CLIENT_CA_KEY CONTROL_IMAGE PROMETHEUS_MTLS_CLIENT_CERT PROMETHEUS_MTLS_CLIENT_KEY
  )
  for key in "${regional_forbidden[@]}"; do
    [[ -z "${cfg[${key}]:-}" ]] || host_die "${key} must be empty on a regional Core node"
  done
fi
for key in OBSERVABILITY_TLS_CERT OBSERVABILITY_TLS_KEY OBSERVABILITY_CLIENT_CA; do
  host_validate_absolute_path "${cfg[${key}]}" "${key}"
done
if [[ "${cfg[APP_ENV]}" == production ]]; then
  [[ "${cfg[ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS]}" == false ]] || host_die "production forbids legacy HMAC transport credentials"
  [[ -z "${cfg[CREDENTIAL_SIGNING_SECRET]:-}" ]] || host_die "production forbids CREDENTIAL_SIGNING_SECRET"
fi

for optional_gateway in OPENVPN IKEV2; do
  enabled_key="${optional_gateway}_ENABLED"
  image_key="${optional_gateway}_IMAGE"
  enabled="${cfg[${enabled_key}]:-false}"
  [[ "${enabled}" == true || "${enabled}" == false ]] || host_die "${enabled_key} must be true or false"
  if [[ "${enabled}" == true ]]; then
    host_require_env cfg "${image_key}"
    host_validate_digest_image "${cfg[${image_key}]}" "${image_key}"
  fi
done
if [[ "${cfg[MASQUE_ENABLED]:-false}" == true ]]; then
  for key in MASQUE_PORT MASQUE_HOST_PORT MASQUE_TLS_CERT MASQUE_TLS_KEY MASQUE_URI_TEMPLATE MASQUE_SERVER_ID MASQUE_MAX_CLIENTS TRANSPORT_CLUSTER_ID; do
    host_require_env cfg "${key}"
  done
  host_validate_port "${cfg[MASQUE_HOST_PORT]}" MASQUE_HOST_PORT 1024
fi
if [[ "${cfg[PROXY_ENABLED]:-false}" == true ]]; then
  for key in PROXY_PORT PROXY_HOST_PORT PROXY_MAX_CONNS_PER_USER PROXY_TLS_ENABLED PROXY_TLS_TERMINATED_BY_NGINX PROXY_SERVER_ID TRANSPORT_CLUSTER_ID; do
    host_require_env cfg "${key}"
  done
fi
if [[ "${cfg[WSS_TUNNEL_ENABLED]:-false}" == true ]]; then
  host_require_env cfg WSS_TUNNEL_SERVER_ID
  host_require_env cfg WSS_TUNNEL_MAX_CLIENTS
  host_require_env cfg TRANSPORT_CLUSTER_ID
fi

install -d -m 0700 -- "$(dirname -- "${output_dir}")"
staging_dir="$(mktemp -d "$(dirname -- "${output_dir}")/.midorivpn-render.XXXXXX")"
checksum_file="$(mktemp "${TMPDIR:-/tmp}/midorivpn-checksums.XXXXXX")"
cleanup() { rm -rf -- "${staging_dir}"; rm -f -- "${checksum_file}"; }
trap cleanup EXIT
install -d -m 0700 "${staging_dir}/rootless/env" "${staging_dir}/rootless/config" "${staging_dir}/rootful"

write_env_file() {
  local env_destination="$1"
  shift
  : > "${env_destination}"
  chmod 0600 "${env_destination}"
  local key
  for key in "$@"; do
    if [[ -v "cfg[${key}]" ]]; then
      printf '%s=%s\n' "${key}" "${cfg[${key}]}" >> "${env_destination}"
    fi
  done
}

core_keys=(
  DEPLOYMENT_PROFILE CORE_NODE_NAME APP_ENV VPN_CORE_PORT PUBLIC_BASE_URL CORS_ALLOWED_ORIGINS
  TRUSTED_PROXIES EXTENSION_CALLBACK_PATH ALLOWED_EXTENSION_ORIGINS CONTROL_NODE_ID
  CONTROL_NODE_PRIVATE_KEY NODE_AUTHORIZED_KEYS NODE_REVOKED_IDS NODE_AUTH_REDIS_URL
  TRANSPORT_TOKEN_ISSUER TRANSPORT_TOKEN_AUTHORIZED_KEYS TRANSPORT_CLUSTER_ID
  ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS CREDENTIAL_SIGNING_SECRET OBSERVABILITY_MTLS_PORT
  OBSERVABILITY_TLS_CERT OBSERVABILITY_TLS_KEY OBSERVABILITY_CLIENT_CA
  OBSERVABILITY_ALLOWED_CLIENT_URI OBSERVABILITY_HOST_BIND NODE_CONTROL_URL CORE_NODE_ID
  CORE_NODE_STATE_DIR CORE_NODE_ENROLLMENT_TOKEN_FILE CORE_NODE_MAX_PEERS
  NODE_SECRET_FINGERPRINTS NODE_EXTERNAL_TRANSPORTS CONTROL_DATA_ENCRYPTION_KEY WG_INTERFACE
  WG_PORT WG_SUBNET WG_CONFIG_DIR WG_ENDPOINT VPN_DNS VPN_CLIENT_CA_CERT VPN_CLIENT_CA_KEY
  VPN_CLIENT_CERT_TTL_HOURS VPN_CLIENT_CRL_URL DATABASE_POOL_MAX_CONNS DATABASE_POOL_MIN_CONNS
  AUTHENTIK_ISSUER AUTHENTIK_CLIENT_ID AUTHENTIK_CLIENT_SECRET AUTHENTIK_JWKS_URL
  AUTHENTIK_INTROSPECTION_URL OAUTH_ALLOWED_REDIRECT_URIS CONTROL_OAUTH_REDIRECT_URI
  CORE_TLS_SKIP_VERIFY CORE_ALLOW_INSECURE_HTTP CORE_ALLOWED_HOSTS RATE_LIMIT_RPS RATE_LIMIT_BURST
  CONNECT_RATE_LIMIT_RPS CONNECT_RATE_LIMIT_BURST MAX_DEVICES_PER_USER PROXY_ENABLED PROXY_PORT
  PROXY_MAX_CONNS_PER_USER PROXY_TLS_ENABLED PROXY_TLS_TERMINATED_BY_NGINX PROXY_TLS_CERT
  PROXY_TLS_KEY PROXY_SERVER_ID WSS_TUNNEL_ENABLED WSS_TUNNEL_SERVER_ID WSS_TUNNEL_MAX_CLIENTS
  MASQUE_ENABLED MASQUE_PORT MASQUE_HOST_PORT MASQUE_TLS_CERT MASQUE_TLS_KEY MASQUE_URI_TEMPLATE MASQUE_SERVER_ID
  MASQUE_MAX_CLIENTS WS_MAX_GLOBAL WS_MAX_FREE WS_MAX_BASIC WS_MAX_MEDIUM WS_MAX_PRO WS_MAX_ADMIN
  ASTIAN_PAYMENT_URL ASTIAN_PAYMENT_INTERNAL_TOKEN
)
if [[ "${profile}" == principal ]]; then
  core_keys+=(POSTGRES_RUNTIME_USER POSTGRES_RUNTIME_PASSWORD POSTGRES_DB REDIS_PASSWORD REDIS_DB)
else
  core_keys+=(REDIS_PASSWORD REDIS_DB)
fi
write_env_file "${staging_dir}/rootless/env/core.env" "${core_keys[@]}"
printf 'REDIS_HOST=127.0.0.1\nREDIS_PORT=6379\n' >> "${staging_dir}/rootless/env/core.env"
if [[ "${profile}" == principal ]]; then
  printf 'DATABASE_URL=\nPOSTGRES_HOST=127.0.0.1\nPOSTGRES_PORT=6432\nPOSTGRES_SSLMODE=disable\n' >> "${staging_dir}/rootless/env/core.env"
fi

write_env_file "${staging_dir}/rootless/env/redis.env" REDIS_PASSWORD

if [[ "${profile}" == principal ]]; then
  write_env_file "${staging_dir}/rootless/env/postgres.env" POSTGRES_ADMIN_USER POSTGRES_ADMIN_PASSWORD POSTGRES_DB
  printf 'POSTGRES_USER=%s\nPOSTGRES_PASSWORD=%s\nPOSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=scram-sha-256\nPOSTGRES_HOST_AUTH_METHOD=scram-sha-256\n' \
    "${cfg[POSTGRES_ADMIN_USER]}" "${cfg[POSTGRES_ADMIN_PASSWORD]}" >> "${staging_dir}/rootless/env/postgres.env"
  write_env_file "${staging_dir}/rootless/env/db-policy.env" POSTGRES_ADMIN_USER POSTGRES_ADMIN_PASSWORD POSTGRES_OWNER_ROLE POSTGRES_MIGRATOR_USER POSTGRES_MIGRATOR_PASSWORD POSTGRES_RUNTIME_USER POSTGRES_RUNTIME_PASSWORD POSTGRES_BACKUP_USER POSTGRES_BACKUP_PASSWORD POSTGRES_DB
  printf 'PGPASSWORD=%s\n' "${cfg[POSTGRES_ADMIN_PASSWORD]}" >> "${staging_dir}/rootless/env/db-policy.env"
  write_env_file "${staging_dir}/rootless/env/migrate.env" POSTGRES_MIGRATOR_USER POSTGRES_MIGRATOR_PASSWORD POSTGRES_DB
  printf 'POSTGRES_MIGRATION_HOST=127.0.0.1\nPOSTGRES_MIGRATION_PORT=5432\nPOSTGRES_MIGRATION_SSLMODE=disable\n' >> "${staging_dir}/rootless/env/migrate.env"
  write_env_file "${staging_dir}/rootless/env/pgbouncer.env" POSTGRES_RUNTIME_USER POSTGRES_RUNTIME_PASSWORD POSTGRES_DB PGBOUNCER_ADMIN_USER PGBOUNCER_ADMIN_PASSWORD PGBOUNCER_MAX_CLIENT_CONN PGBOUNCER_DEFAULT_POOL_SIZE PGBOUNCER_MIN_POOL_SIZE PGBOUNCER_RESERVE_POOL_SIZE PGBOUNCER_MAX_DB_CONNECTIONS
  printf 'POSTGRES_HOST=127.0.0.1\nPOSTGRES_PORT=5432\n' >> "${staging_dir}/rootless/env/pgbouncer.env"
  write_env_file "${staging_dir}/rootless/env/control.env" PUBLIC_BASE_URL CONTROL_CONTAINER_PORT
  : > "${staging_dir}/rootless/env/grafana.env"
  chmod 0600 "${staging_dir}/rootless/env/grafana.env"
  printf 'GF_SECURITY_ADMIN_USER=%s\nGF_SECURITY_ADMIN_PASSWORD=%s\n' "${cfg[GRAFANA_ADMIN_USER]}" "${cfg[GRAFANA_ADMIN_PASSWORD]}" >> "${staging_dir}/rootless/env/grafana.env"

  install -m 0600 "${SOURCE_ROOT}/deploy/postgres/configure-roles.sql" "${staging_dir}/rootless/config/configure-roles.sql"
  install -m 0600 "${SOURCE_ROOT}/deploy/postgres/check-policy.sql" "${staging_dir}/rootless/config/check-policy.sql"
  escape_sed() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }
  sed \
    -e "s|__OBSERVABILITY_CLUSTER__|$(escape_sed "${cfg[OBSERVABILITY_CLUSTER]}")|g" \
    -e "s|__VPN_CORE_METRICS_TARGET__|$(escape_sed "${cfg[VPN_CORE_METRICS_TARGET]}")|g" \
    -e "s|__CORE_NODE_NAME__|$(escape_sed "${cfg[CORE_NODE_NAME]}")|g" \
    "${SOURCE_ROOT}/deploy/observability/prometheus.yml.template" > "${staging_dir}/rootless/config/prometheus.yml"
  install -m 0600 "${SOURCE_ROOT}/deploy/observability/alerts.yml" "${staging_dir}/rootless/config/alerts.yml"
  install -m 0600 "${SOURCE_ROOT}/deploy/observability/grafana-dashboard-provider.yml" "${staging_dir}/rootless/config/grafana-dashboard-provider.yml"
  install -m 0600 "${SOURCE_ROOT}/deploy/grafana/midori-vpn-dashboard.json" "${staging_dir}/rootless/config/midori-vpn-dashboard.json"
  sed \
    -e "s|__PROMETHEUS_URL__|http://midorivpn-prometheus:9090|g" \
    "${SOURCE_ROOT}/deploy/observability/grafana-datasource.yml.template" > "${staging_dir}/rootless/config/grafana-datasource.yml"
  chmod 0600 "${staging_dir}/rootless/config/"*
fi

cat > "${staging_dir}/rootless/midorivpn.network" <<EOF
[Unit]
Description=MidoriVPN private application network

[Network]
NetworkName=midorivpn-net
Driver=bridge
EOF

{
  cat <<EOF
[Unit]
Description=MidoriVPN ${profile} pod
After=network-online.target
Wants=network-online.target

[Pod]
PodName=midorivpn-${cfg[CORE_NODE_NAME]}
Network=midorivpn.network
PodmanArgs=--infra-image=${cfg[POD_INFRA_IMAGE]} --infra-command=/pause
PublishPort=127.0.0.1:${cfg[VPN_CORE_HOST_PORT]}:${cfg[VPN_CORE_PORT]}/tcp
PublishPort=${cfg[WG_PORT]}:${cfg[WG_PORT]}/udp
EOF
  if [[ "${profile}" == core-node ]]; then
    printf 'PublishPort=%s:%s:%s/tcp\n' "${cfg[OBSERVABILITY_HOST_BIND]}" "${cfg[OBSERVABILITY_MTLS_PORT]}" "${cfg[OBSERVABILITY_MTLS_PORT]}"
  fi
  if [[ "${cfg[PROXY_ENABLED]:-false}" == true ]]; then
    printf 'PublishPort=127.0.0.1:%s:%s/tcp\n' "${cfg[PROXY_HOST_PORT]}" "${cfg[PROXY_PORT]}"
  fi
  if [[ "${cfg[MASQUE_ENABLED]:-false}" == true ]]; then
    printf 'PublishPort=%s:%s/udp\n' "${cfg[MASQUE_HOST_PORT]}" "${cfg[MASQUE_PORT]}"
  fi
  if [[ "${profile}" == principal ]]; then
    printf 'PublishPort=127.0.0.1:%s:%s/tcp\n' "${cfg[CONTROL_HOST_PORT]}" "${cfg[CONTROL_CONTAINER_PORT]}"
  fi
  cat <<'EOF'

[Service]
Restart=always
TimeoutStartSec=900

[Install]
WantedBy=default.target
EOF
} > "${staging_dir}/rootless/midorivpn.pod"

cat > "${staging_dir}/rootless/midorivpn-redis-data.volume" <<'EOF'
[Volume]
VolumeName=midorivpn-redis-data
EOF
cat > "${staging_dir}/rootless/midorivpn-wg-config.volume" <<'EOF'
[Volume]
VolumeName=midorivpn-wg-config
EOF

cat > "${staging_dir}/rootless/midorivpn-redis.container" <<EOF
[Unit]
Description=MidoriVPN private Redis
Requires=midorivpn-pod.service
After=midorivpn-pod.service

[Container]
ContainerName=midorivpn-redis
Pod=midorivpn.pod
Image=${cfg[REDIS_IMAGE]}
Pull=never
EnvironmentFile=${runtime_dir}/env/redis.env
Volume=midorivpn-redis-data.volume:/data:Z
ReadOnly=true
NoNewPrivileges=true
DropCapability=all
Tmpfs=/run:rw,noexec,nosuid,nodev,size=8m
Exec=sh -ceu 'exec redis-server --requirepass "\$REDIS_PASSWORD"'
HealthCmd=sh -ceu 'REDISCLI_AUTH="\$REDIS_PASSWORD" redis-cli ping | grep -qx PONG'
HealthInterval=3s
HealthTimeout=3s
HealthRetries=20
Notify=healthy

[Service]
Restart=always
RestartSec=5
TimeoutStartSec=120
EOF

core_after="midorivpn-redis.service"
if [[ "${profile}" == principal ]]; then
  cat > "${staging_dir}/rootless/midorivpn-postgres-data.volume" <<'EOF'
[Volume]
VolumeName=midorivpn-postgres-data-v18
EOF
  cat > "${staging_dir}/rootless/midorivpn-postgres.container" <<EOF
[Unit]
Description=MidoriVPN PostgreSQL 18
Requires=midorivpn-pod.service
After=midorivpn-pod.service

[Container]
ContainerName=midorivpn-postgres
Pod=midorivpn.pod
Image=${cfg[POSTGRES_IMAGE]}
Pull=never
EnvironmentFile=${runtime_dir}/env/postgres.env
Volume=midorivpn-postgres-data.volume:/var/lib/postgresql:Z
NoNewPrivileges=true
DropCapability=all
Exec=postgres -c shared_preload_libraries=pg_stat_statements -c password_encryption=scram-sha-256 -c log_connections=off -c log_disconnections=off -c log_statement=none
HealthCmd=sh -ceu 'PGPASSWORD="\$POSTGRES_PASSWORD" pg_isready -U "\$POSTGRES_USER" -d "\$POSTGRES_DB"'
HealthInterval=3s
HealthTimeout=3s
HealthRetries=30
Notify=healthy

[Service]
Restart=always
RestartSec=5
TimeoutStartSec=180
EOF

  for phase in prepare finalize; do
    if [[ "${phase}" == prepare ]]; then
      dependency="midorivpn-postgres.service midorivpn-redis.service"
      after="midorivpn-postgres.service midorivpn-redis.service"
    else
      dependency="midorivpn-migrate.service"
      after="midorivpn-migrate.service"
    fi
    cat > "${staging_dir}/rootless/midorivpn-db-${phase}.container" <<EOF
[Unit]
Description=MidoriVPN PostgreSQL policy ${phase}
Requires=${dependency}
After=${after}

[Container]
ContainerName=midorivpn-db-${phase}
Pod=midorivpn.pod
Image=${cfg[POSTGRES_IMAGE]}
Pull=never
EnvironmentFile=${runtime_dir}/env/db-policy.env
Volume=${runtime_dir}/config/configure-roles.sql:/run/midorivpn/configure-roles.sql:ro,Z
Volume=${runtime_dir}/config/check-policy.sql:/run/midorivpn/check-policy.sql:ro,Z
ReadOnly=true
NoNewPrivileges=true
DropCapability=all
Entrypoint=/bin/sh
Exec=-ceu 'psql -h 127.0.0.1 -U "\$POSTGRES_ADMIN_USER" -d postgres --no-psqlrc -v ON_ERROR_STOP=1 -f /run/midorivpn/configure-roles.sql; psql -h 127.0.0.1 -U "\$POSTGRES_ADMIN_USER" -d "\$POSTGRES_DB" --no-psqlrc -v ON_ERROR_STOP=1 -f /run/midorivpn/check-policy.sql'

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=180
EOF
  done

  cat > "${staging_dir}/rootless/midorivpn-migrate.container" <<EOF
[Unit]
Description=MidoriVPN database migrations
Requires=midorivpn-db-prepare.service
After=midorivpn-db-prepare.service

[Container]
ContainerName=midorivpn-migrate
Pod=midorivpn.pod
Image=${cfg[CORE_IMAGE]}
Pull=never
EnvironmentFile=${runtime_dir}/env/migrate.env
ReadOnly=true
NoNewPrivileges=true
DropCapability=all
Entrypoint=/usr/local/bin/midorivpn-migrate

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=300
EOF

  cat > "${staging_dir}/rootless/midorivpn-pgbouncer.container" <<EOF
[Unit]
Description=MidoriVPN PgBouncer transaction pool
Requires=midorivpn-db-finalize.service
After=midorivpn-db-finalize.service

[Container]
ContainerName=midorivpn-pgbouncer
Pod=midorivpn.pod
Image=${cfg[PGBOUNCER_IMAGE]}
Pull=never
EnvironmentFile=${runtime_dir}/env/pgbouncer.env
ReadOnly=true
ReadOnlyTmpfs=false
NoNewPrivileges=true
DropCapability=all
Tmpfs=/run/pgbouncer:rw,noexec,nosuid,nodev,size=4m,mode=1733
HealthCmd=sh -ceu 'PGPASSWORD="\$POSTGRES_RUNTIME_PASSWORD" pg_isready -h 127.0.0.1 -p 6432 -U "\$POSTGRES_RUNTIME_USER" -d "\$POSTGRES_DB"'
HealthInterval=3s
HealthTimeout=3s
HealthRetries=20
Notify=healthy

[Service]
Restart=always
RestartSec=5
TimeoutStartSec=120
EOF
  core_after="midorivpn-pgbouncer.service"
fi

{
  cat <<EOF
[Unit]
Description=MidoriVPN Core ${profile}
Requires=${core_after}
After=${core_after}

[Container]
ContainerName=midorivpn-core
Pod=midorivpn.pod
Image=${cfg[CORE_IMAGE]}
Pull=never
EnvironmentFile=${runtime_dir}/env/core.env
Volume=midorivpn-wg-config.volume:${cfg[WG_CONFIG_DIR]}:Z
EOF
  if [[ -n "${cfg[CORE_NODE_STATE_HOST_DIR]:-}" ]]; then
    printf 'Volume=%s:%s:Z\n' "${cfg[CORE_NODE_STATE_HOST_DIR]}" "${cfg[CORE_NODE_STATE_DIR]}"
  fi
  for tls_key in OBSERVABILITY_TLS_CERT OBSERVABILITY_TLS_KEY OBSERVABILITY_CLIENT_CA; do
    if [[ -n "${cfg[${tls_key}]:-}" ]]; then
      printf 'Volume=%s:%s:ro,z\n' "${cfg[${tls_key}]}" "${cfg[${tls_key}]}"
    fi
  done
  if [[ -n "${cfg[NODE_EXTERNAL_TRANSPORTS]:-}" ]]; then
    printf 'Volume=/run/midorivpn-health:/run/midorivpn-health:ro\n'
  fi
  cat <<'EOF'
AddDevice=/dev/net/tun
DropCapability=all
AddCapability=NET_ADMIN
AddCapability=NET_RAW
NoNewPrivileges=true
HealthCmd=sh -ceu 'wget -q -O /dev/null "http://127.0.0.1:$VPN_CORE_PORT/readyz"'
HealthInterval=5s
HealthTimeout=4s
HealthRetries=24
Notify=healthy

[Service]
Restart=always
RestartSec=5
TimeoutStartSec=180

[Install]
WantedBy=default.target
EOF
} > "${staging_dir}/rootless/midorivpn-core.container"

if [[ "${profile}" == principal ]]; then
  cat > "${staging_dir}/rootless/midorivpn-control.container" <<EOF
[Unit]
Description=MidoriVPN Control web
Requires=midorivpn-core.service
After=midorivpn-core.service

[Container]
ContainerName=midorivpn-control
Pod=midorivpn.pod
Image=${cfg[CONTROL_IMAGE]}
Pull=never
EnvironmentFile=${runtime_dir}/env/control.env
ReadOnly=true
NoNewPrivileges=true
DropCapability=all
Tmpfs=/var/cache/nginx:rw,noexec,nosuid,nodev,size=16m
Tmpfs=/var/run:rw,noexec,nosuid,nodev,size=4m
HealthCmd=sh -ceu 'wget -q -O /dev/null "http://127.0.0.1:\$CONTROL_CONTAINER_PORT/"'
HealthInterval=5s
HealthTimeout=4s
HealthRetries=24
Notify=healthy

[Service]
Restart=always
RestartSec=5
TimeoutStartSec=120

[Install]
WantedBy=default.target
EOF

  cat > "${staging_dir}/rootless/midorivpn-prometheus-data.volume" <<'EOF'
[Volume]
VolumeName=midorivpn-prometheus-data
EOF
  cat > "${staging_dir}/rootless/midorivpn-grafana-data.volume" <<'EOF'
[Volume]
VolumeName=midorivpn-grafana-data
EOF
  cat > "${staging_dir}/rootless/midorivpn-prometheus.container" <<EOF
[Unit]
Description=MidoriVPN private Prometheus
Requires=midorivpn-core.service
After=midorivpn-core.service

[Container]
ContainerName=midorivpn-prometheus
Network=midorivpn.network
Image=${cfg[PROMETHEUS_IMAGE]}
Pull=never
PublishPort=127.0.0.1:${cfg[PROMETHEUS_HOST_PORT]}:9090
Volume=${runtime_dir}/config/prometheus.yml:/etc/prometheus/prometheus.yml:ro,Z
Volume=${runtime_dir}/config/alerts.yml:/etc/prometheus/rules/midorivpn.yml:ro,Z
Volume=${cfg[PROMETHEUS_MTLS_CA]}:/etc/prometheus/mtls/ca.crt:ro,z
Volume=${cfg[PROMETHEUS_MTLS_CLIENT_CERT]}:/etc/prometheus/mtls/client.crt:ro,z
Volume=${cfg[PROMETHEUS_MTLS_CLIENT_KEY]}:/etc/prometheus/mtls/client.key:ro,z
Volume=midorivpn-prometheus-data.volume:/prometheus:Z
ReadOnly=true
NoNewPrivileges=true
DropCapability=all
Tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m
Exec=--config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus --storage.tsdb.retention.time=15d --web.listen-address=0.0.0.0:9090

[Service]
Restart=always
RestartSec=5
TimeoutStartSec=90

[Install]
WantedBy=default.target
EOF
  cat > "${staging_dir}/rootless/midorivpn-grafana.container" <<EOF
[Unit]
Description=MidoriVPN private Grafana
Requires=midorivpn-prometheus.service
After=midorivpn-prometheus.service

[Container]
ContainerName=midorivpn-grafana
Network=midorivpn.network
Image=${cfg[GRAFANA_IMAGE]}
Pull=never
PublishPort=127.0.0.1:${cfg[GRAFANA_HOST_PORT]}:3000
EnvironmentFile=${runtime_dir}/env/grafana.env
Environment=GF_AUTH_ANONYMOUS_ENABLED=false
Environment=GF_USERS_ALLOW_SIGN_UP=false
Environment=GF_ANALYTICS_REPORTING_ENABLED=false
Environment=GF_ANALYTICS_CHECK_FOR_UPDATES=false
Environment=GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false
Environment=GF_SECURITY_DISABLE_GRAVATAR=true
Volume=${runtime_dir}/config/grafana-datasource.yml:/etc/grafana/provisioning/datasources/midorivpn.yml:ro,Z
Volume=${runtime_dir}/config/grafana-dashboard-provider.yml:/etc/grafana/provisioning/dashboards/midorivpn.yml:ro,Z
Volume=${runtime_dir}/config/midori-vpn-dashboard.json:/var/lib/grafana/dashboards/midori-vpn-dashboard.json:ro,Z
Volume=midorivpn-grafana-data.volume:/var/lib/grafana:Z
ReadOnly=true
NoNewPrivileges=true
DropCapability=all
Tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m
Tmpfs=/var/log/grafana:rw,noexec,nosuid,nodev,size=16m

[Service]
Restart=always
RestartSec=5
TimeoutStartSec=90

[Install]
WantedBy=default.target
EOF
fi

for gateway in openvpn ikev2; do
  upper="${gateway^^}"
  if [[ "${cfg[${upper}_ENABLED]:-false}" == true ]]; then
    image="${cfg[${upper}_IMAGE]}"
    cat > "${staging_dir}/rootful/midorivpn-${gateway}.container" <<EOF
[Unit]
Description=MidoriVPN ${gateway} rootful gateway
After=network-online.target
Wants=network-online.target

[Container]
Image=${image}
Pull=never
ContainerName=midorivpn-${gateway}
Network=host
EnvironmentFile=/etc/midorivpn/${gateway}.env
Volume=/etc/midorivpn/pki:/etc/midorivpn/pki:ro
Volume=/run/midorivpn-health:/run/midorivpn-health:rw
ReadOnly=true
NoNewPrivileges=true
DropCapability=all
AddCapability=NET_ADMIN
AddCapability=NET_RAW
AddCapability=NET_BIND_SERVICE
EOF
    if [[ "${gateway}" == openvpn ]]; then
      printf 'AddDevice=/dev/net/tun\n' >> "${staging_dir}/rootful/midorivpn-${gateway}.container"
    fi
    cat >> "${staging_dir}/rootful/midorivpn-${gateway}.container" <<'EOF'
Tmpfs=/tmp:rw,nodev,nosuid,noexec,mode=0700

[Service]
Restart=on-failure
RestartSec=5
TimeoutStartSec=90
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
  fi
done

if find "${staging_dir}" -type f -print0 | xargs -0 rg -n '(^|[=/])latest($|[[:space:]])|AutoUpdate=|[.]build$' >/dev/null; then
  host_die "rendered deployment contains a mutable image or host build directive"
fi

(
  cd "${staging_dir}"
  find . -type f -print0 | sort -z | xargs -0 sha256sum
) > "${checksum_file}"
install -m 0600 "${checksum_file}" "${staging_dir}/SHA256SUMS"
rm -f -- "${checksum_file}"
mv -- "${staging_dir}" "${output_dir}"
trap - EXIT
host_info "Rendered immutable ${profile} deployment: ${output_dir}"

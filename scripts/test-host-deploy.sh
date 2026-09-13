#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_DIR="${ROOT}/deploy/host"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/midorivpn-host-test.XXXXXX")"
cleanup() { rm -rf -- "${test_root}"; }
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

bash "${ROOT}/scripts/test-management-pki.sh" >/dev/null

assert_contains() {
  local file="$1" expected="$2"
  grep -Fqx -- "${expected}" "${file}" || fail "${file} does not contain ${expected}"
}

tag_a="2.0.0-rc.1"
tag_b="2.0.0-rc.2"

target_env="${test_root}/config/midorivpn.env"
values_env="${test_root}/values.env"
install -d -m 0700 "$(dirname -- "${target_env}")"
cat > "${target_env}" <<EOF
# keep this operator comment
UNMANAGED_LOCAL=value that stays
DOMAIN=old.example.test
CORE_IMAGE=registry.example.test/midori/core:${tag_a}
EOF
cat > "${values_env}" <<EOF
DOMAIN=new.example.test
CORE_IMAGE=registry.example.test/midori/core:${tag_b}
EOF
chmod 0600 "${target_env}" "${values_env}"
bash "${HOST_DIR}/patch-env.sh" --env-file "${target_env}" --values-file "${values_env}" --backup-dir "${test_root}/backups" --backup-record "${test_root}/env-backup-record" >/dev/null
assert_contains "${target_env}" '# keep this operator comment'
assert_contains "${target_env}" 'UNMANAGED_LOCAL=value that stays'
assert_contains "${target_env}" 'DOMAIN=new.example.test'
assert_contains "${target_env}" "CORE_IMAGE=registry.example.test/midori/core:${tag_b}"
[[ "$(stat -c '%a' "${target_env}")" == 600 ]] || fail "patched environment is not mode 0600"
[[ "$(find "${test_root}/backups" -type f | wc -l)" == 1 ]] || fail "patch did not create exactly one backup"
env_backup="$(find "${test_root}/backups" -type f -print -quit)"
[[ "$(<"${test_root}/env-backup-record")" == "${env_backup}" ]] || fail "patcher did not record the exact rollback file"

cat > "${test_root}/unknown.env" <<'EOF'
UNMANAGED_LOCAL=must-not-change
EOF
chmod 0600 "${test_root}/unknown.env"
if bash "${HOST_DIR}/patch-env.sh" --env-file "${target_env}" --values-file "${test_root}/unknown.env" >/dev/null 2>&1; then
  fail "patch accepted an unmanaged key"
fi
assert_contains "${target_env}" 'UNMANAGED_LOCAL=value that stays'

cat > "${test_root}/duplicate.env" <<'EOF'
DOMAIN=one.example.test
DOMAIN=two.example.test
EOF
chmod 0600 "${test_root}/duplicate.env"
if bash "${HOST_DIR}/patch-env.sh" --env-file "${target_env}" --values-file "${test_root}/duplicate.env" >/dev/null 2>&1; then
  fail "patch accepted duplicate input"
fi
bash "${HOST_DIR}/restore-env.sh" --env-file "${target_env}" --backup-file "${env_backup}" >/dev/null
assert_contains "${target_env}" 'DOMAIN=old.example.test'
assert_contains "${target_env}" 'UNMANAGED_LOCAL=value that stays'

render_env="${test_root}/render.env"
cat > "${render_env}" <<EOF
DEPLOYMENT_PROFILE=principal
CORE_NODE_NAME=main
APP_ENV=production
CORE_IMAGE=registry.example.test/midori/core:${tag_a}
CONTROL_IMAGE=registry.example.test/midori/control:${tag_a}
POD_INFRA_IMAGE=registry.example.test/base/pause:3.10.1
POSTGRES_IMAGE=registry.example.test/base/postgres:18.6.0-alpine
PGBOUNCER_IMAGE=registry.example.test/midori/pgbouncer:1.25.2
REDIS_IMAGE=registry.example.test/base/redis:8.2.1-alpine
PROMETHEUS_IMAGE=registry.example.test/base/prometheus:3.14.0
GRAFANA_IMAGE=registry.example.test/base/grafana:13.2.1
VPN_CORE_PORT=8085
VPN_CORE_HOST_PORT=8085
CONTROL_CONTAINER_PORT=80
CONTROL_HOST_PORT=5173
PROMETHEUS_HOST_PORT=9090
GRAFANA_HOST_PORT=3000
WG_PORT=51820
WG_INTERFACE=wg0
WG_SUBNET=10.88.0.0/24
WG_CONFIG_DIR=/etc/wireguard
WG_ENDPOINT=vpn.example.test
VPN_DNS=1.1.1.1
POSTGRES_ADMIN_USER=admin
POSTGRES_ADMIN_PASSWORD=admin-secret
POSTGRES_OWNER_ROLE=owner
POSTGRES_MIGRATOR_USER=migrator
POSTGRES_MIGRATOR_PASSWORD=migrator-secret
POSTGRES_RUNTIME_USER=runtime
POSTGRES_RUNTIME_PASSWORD=runtime-secret
POSTGRES_BACKUP_USER=backup
POSTGRES_BACKUP_PASSWORD=backup-secret
PGBOUNCER_ADMIN_USER=pooladmin
PGBOUNCER_ADMIN_PASSWORD=pool-secret
POSTGRES_DB=midorivpn
REDIS_PASSWORD=redis-secret
REDIS_DB=0
PGBOUNCER_MAX_CLIENT_CONN=200
PGBOUNCER_DEFAULT_POOL_SIZE=16
PGBOUNCER_MIN_POOL_SIZE=2
PGBOUNCER_RESERVE_POOL_SIZE=4
PGBOUNCER_MAX_DB_CONNECTIONS=24
OBSERVABILITY_NETWORK=midorivpn-observability
OBSERVABILITY_CONFIG_DIR=/home/midorivpn/.config/midorivpn/observability
OBSERVABILITY_CLUSTER=main
VPN_CORE_METRICS_TARGET=midorivpn-core:9443
PROMETHEUS_MTLS_CA=/etc/midorivpn/observability/ca.crt
PROMETHEUS_MTLS_CLIENT_CERT=/etc/midorivpn/observability/client.crt
PROMETHEUS_MTLS_CLIENT_KEY=/etc/midorivpn/observability/client.key
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=grafana-secret-strong
PUBLIC_BASE_URL=https://vpn.example.test
CONTROL_NODE_ID=control-key
CONTROL_NODE_PRIVATE_KEY=control-private-secret
NODE_AUTHORIZED_KEYS=control-key=public-key
NODE_AUTH_REDIS_URL=redis://:redis-secret@127.0.0.1:6379/0
CONTROL_DATA_ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
TRANSPORT_TOKEN_ISSUER=https://vpn.example.test
TRANSPORT_TOKEN_AUTHORIZED_KEYS=control-key=public-key
ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS=false
CORS_ALLOWED_ORIGINS=https://vpn.example.test
EXTENSION_CALLBACK_PATH=/extension/callback
AUTHENTIK_ISSUER=https://auth.example.test/application/o/midorivpn/
AUTHENTIK_CLIENT_ID=midorivpn
OAUTH_ALLOWED_REDIRECT_URIS=https://vpn.example.test/extension/callback
CONTROL_OAUTH_REDIRECT_URI=https://vpn.example.test/api/v1/auth/callback
CORE_TLS_SKIP_VERIFY=false
CORE_ALLOW_INSECURE_HTTP=false
RATE_LIMIT_RPS=20
RATE_LIMIT_BURST=40
CONNECT_RATE_LIMIT_RPS=2
CONNECT_RATE_LIMIT_BURST=4
MAX_DEVICES_PER_USER=5
PROXY_ENABLED=false
PROXY_PORT=8443
PROXY_MAX_CONNS_PER_USER=10
PROXY_TLS_ENABLED=false
PROXY_TLS_TERMINATED_BY_NGINX=true
WSS_TUNNEL_ENABLED=false
WSS_TUNNEL_MAX_CLIENTS=100
MASQUE_ENABLED=false
MASQUE_PORT=443
MASQUE_HOST_PORT=8443
MASQUE_MAX_CLIENTS=100
OBSERVABILITY_MTLS_PORT=9443
OBSERVABILITY_TLS_CERT=/etc/midorivpn/observability/server.crt
OBSERVABILITY_TLS_KEY=/etc/midorivpn/observability/server.key
OBSERVABILITY_CLIENT_CA=/etc/midorivpn/observability/ca.crt
OBSERVABILITY_ALLOWED_CLIENT_URI=spiffe://midorivpn/observability/prometheus
MANAGEMENT_HOST_BIND=10.254.240.1
MANAGEMENT_PEER_ADDRESS=10.254.240.2
MANAGEMENT_HTTPS_PORT=8443
MANAGEMENT_TLS_CERT=/etc/midorivpn/management/server.crt
MANAGEMENT_TLS_KEY=/etc/midorivpn/management/server.key
MANAGEMENT_TLS_CA=/etc/midorivpn/management/ca.crt
WS_MAX_GLOBAL=1000
WS_MAX_FREE=2
WS_MAX_BASIC=5
WS_MAX_MEDIUM=10
WS_MAX_PRO=20
WS_MAX_ADMIN=50
OPENVPN_ENABLED=false
IKEV2_ENABLED=false
EOF
chmod 0600 "${render_env}"
rendered="${test_root}/rendered"
runtime_dir="${test_root}/runtime/midorivpn"
bash "${HOST_DIR}/render-quadlets.sh" --env-file "${render_env}" --output-dir "${rendered}" --runtime-dir "${runtime_dir}" >/dev/null
[[ "$(stat -c '%a' "${rendered}")" == 700 ]] || fail "rendered directory is not private"
find "${rendered}/rootless/env" -type f ! -perm 0600 -print -quit | grep -q . && fail "rendered environment is not mode 0600"
if rg -n '(^|[=/])latest($|[[:space:]])|AutoUpdate=|[.]build$' "${rendered}" >/dev/null; then
  fail "render contains mutable deployment directives"
fi
grep -Fq 'admin-secret' "${rendered}/rootless/env/db-policy.env" || fail "policy environment is incomplete"
if grep -Fq 'admin-secret' "${rendered}/rootless/env/core.env"; then
  fail "database administrator secret leaked to Core"
fi
if grep -Fq 'grafana-secret' "${rendered}/rootless/env/core.env"; then
  fail "Grafana secret leaked to Core"
fi
assert_contains "${rendered}/rootless/env/grafana.env" 'GF_SECURITY_ADMIN_USER=admin'
assert_contains "${rendered}/rootless/env/grafana.env" 'GF_SECURITY_ADMIN_PASSWORD=grafana-secret-strong'
grep -Fq "Image=registry.example.test/midori/core:${tag_a}" "${rendered}/rootless/midorivpn-core.container" || fail "Core version tag missing"
assert_contains "${rendered}/rootless/env/core.env" 'MANAGEMENT_TLS_CA=/etc/midorivpn/management/ca.crt'
grep -Fq 'Volume=/etc/midorivpn/management/ca.crt:/etc/midorivpn/management/ca.crt:ro,z' "${rendered}/rootless/midorivpn-core.container" || fail "management CA is not mounted read-only"
quadlet_bin=''
for candidate in /usr/libexec/podman/quadlet /usr/lib/podman/quadlet; do
  if [[ -x "${candidate}" ]]; then
    quadlet_bin="${candidate}"
    break
  fi
done
if [[ -n "${quadlet_bin}" ]]; then
  QUADLET_UNIT_DIRS="${rendered}/rootless" "${quadlet_bin}" -user -dryrun > "${test_root}/quadlet-dryrun.txt" 2>&1 || {
    tail -n 160 "${test_root}/quadlet-dryrun.txt" >&2
    fail "Podman Quadlet rejected the rendered rootless units"
  }
  grep -Fq 'midorivpn-core.service' "${test_root}/quadlet-dryrun.txt" || fail "Quadlet did not generate the Core service"
fi

masque_env="${test_root}/masque.env"
sed 's/^MASQUE_ENABLED=false$/MASQUE_ENABLED=true/' "${render_env}" > "${masque_env}"
cat >> "${masque_env}" <<'EOF'
MASQUE_TLS_CERT=/etc/letsencrypt/live/vpn.example.test/fullchain.pem
MASQUE_TLS_KEY=/etc/letsencrypt/live/vpn.example.test/privkey.pem
MASQUE_URI_TEMPLATE=https://vpn.example.test/masque{?target_host,target_port}
MASQUE_SERVER_ID=10000000-0000-4000-8000-000000000001
TRANSPORT_CLUSTER_ID=20000000-0000-4000-8000-000000000001
EOF
chmod 0600 "${masque_env}"
bash "${HOST_DIR}/render-quadlets.sh" --env-file "${masque_env}" --output-dir "${test_root}/masque-render" --runtime-dir "${runtime_dir}" >/dev/null
grep -Fq 'PublishPort=8443:443/udp' "${test_root}/masque-render/rootless/midorivpn.pod" || fail "rootless MASQUE port translation is incorrect"

gateway_env="${test_root}/gateways.env"
sed -e 's/^OPENVPN_ENABLED=false$/OPENVPN_ENABLED=true/' -e 's/^IKEV2_ENABLED=false$/IKEV2_ENABLED=true/' "${render_env}" > "${gateway_env}"
cat >> "${gateway_env}" <<EOF
OPENVPN_IMAGE=registry.example.test/midori/openvpn:${tag_a}
IKEV2_IMAGE=registry.example.test/midori/ikev2:${tag_a}
EOF
chmod 0600 "${gateway_env}"
bash "${HOST_DIR}/render-quadlets.sh" --env-file "${gateway_env}" --output-dir "${test_root}/gateway-render" --runtime-dir "${runtime_dir}" >/dev/null
[[ -f "${test_root}/gateway-render/rootful/midorivpn-openvpn.container" ]] || fail "OpenVPN rootful unit was not rendered"
[[ -f "${test_root}/gateway-render/rootful/midorivpn-ikev2.container" ]] || fail "IKEv2 rootful unit was not rendered"
if [[ -n "${quadlet_bin}" ]]; then
  QUADLET_UNIT_DIRS="${test_root}/gateway-render/rootful" "${quadlet_bin}" -dryrun > "${test_root}/rootful-quadlet-dryrun.txt" 2>&1 || {
    tail -n 120 "${test_root}/rootful-quadlet-dryrun.txt" >&2
    fail "Podman Quadlet rejected the rendered rootful gateway units"
  }
fi

regional_env="${test_root}/regional.env"
cat > "${regional_env}" <<EOF
DEPLOYMENT_PROFILE=core-node
CORE_NODE_NAME=regional-one
APP_ENV=production
CORE_IMAGE=registry.example.test/midori/core:${tag_a}
POD_INFRA_IMAGE=registry.example.test/base/pause:3.10.1
REDIS_IMAGE=registry.example.test/base/redis:8.2.1-alpine
REDIS_PASSWORD=regional-redis-secret
REDIS_DB=0
VPN_CORE_PORT=8085
VPN_CORE_HOST_PORT=8085
WG_PORT=51820
WG_INTERFACE=wg0
WG_SUBNET=10.89.0.0/24
WG_CONFIG_DIR=/etc/wireguard
WG_ENDPOINT=regional.example.test
VPN_DNS=1.1.1.1
NODE_AUTHORIZED_KEYS=control-key=public-key
NODE_AUTH_REDIS_URL=redis://:regional-redis-secret@127.0.0.1:6379/0
TRANSPORT_TOKEN_ISSUER=https://vpn.example.test
TRANSPORT_TOKEN_AUTHORIZED_KEYS=control-key=public-key
TRANSPORT_CLUSTER_ID=20000000-0000-4000-8000-000000000001
ALLOW_LEGACY_HMAC_TRANSPORT_TOKENS=false
PUBLIC_BASE_URL=https://regional.example.test
CORS_ALLOWED_ORIGINS=https://vpn.example.test
EXTENSION_CALLBACK_PATH=/extension/callback
CORE_TLS_SKIP_VERIFY=false
CORE_ALLOW_INSECURE_HTTP=false
RATE_LIMIT_RPS=20
RATE_LIMIT_BURST=40
CONNECT_RATE_LIMIT_RPS=2
CONNECT_RATE_LIMIT_BURST=4
MAX_DEVICES_PER_USER=100
PROXY_ENABLED=false
PROXY_PORT=8443
PROXY_MAX_CONNS_PER_USER=10
PROXY_TLS_ENABLED=false
PROXY_TLS_TERMINATED_BY_NGINX=true
WSS_TUNNEL_ENABLED=false
WSS_TUNNEL_MAX_CLIENTS=100
MASQUE_ENABLED=false
MASQUE_PORT=443
MASQUE_MAX_CLIENTS=100
WS_MAX_GLOBAL=1000
WS_MAX_FREE=2
WS_MAX_BASIC=5
WS_MAX_MEDIUM=10
WS_MAX_PRO=20
WS_MAX_ADMIN=50
NODE_CONTROL_URL=https://vpn.example.test
CORE_NODE_ID=30000000-0000-4000-8000-000000000001
CORE_NODE_STATE_DIR=/var/lib/midorivpn-node
CORE_NODE_STATE_HOST_DIR=/home/midorivpn/state/regional-one
CORE_NODE_ENROLLMENT_TOKEN_FILE=/var/lib/midorivpn-node/enrollment-token
CORE_NODE_MAX_PEERS=100
OBSERVABILITY_MTLS_PORT=9443
OBSERVABILITY_HOST_BIND=10.0.0.2
OBSERVABILITY_TLS_CERT=/etc/midorivpn/observability/server.crt
OBSERVABILITY_TLS_KEY=/etc/midorivpn/observability/server.key
OBSERVABILITY_CLIENT_CA=/etc/midorivpn/observability/ca.crt
OBSERVABILITY_ALLOWED_CLIENT_URI=spiffe://midorivpn/observability/prometheus
MANAGEMENT_HOST_BIND=10.254.240.2
MANAGEMENT_PEER_ADDRESS=10.254.240.1
MANAGEMENT_HTTPS_PORT=8443
MANAGEMENT_TLS_CERT=/etc/midorivpn/management/server.crt
MANAGEMENT_TLS_KEY=/etc/midorivpn/management/server.key
MANAGEMENT_TLS_CA=/etc/midorivpn/management/ca.crt
OPENVPN_ENABLED=false
IKEV2_ENABLED=false
EOF
chmod 0600 "${regional_env}"
regional_variables="${test_root}/regional-variables.env"
regional_secrets="${test_root}/regional-secrets.env"
: > "${regional_variables}"
: > "${regional_secrets}"
while IFS='=' read -r key value; do
  if [[ "${key}" == CORE_IMAGE || "${key}" == CONTROL_IMAGE ]]; then
    continue
  fi
  classification="$(jq -er --arg key "${key}" '.managed_env[$key]' "${ROOT}/deploy/ci/environment-map.json")"
  if [[ "${classification}" == secret ]]; then
    printf '%s=%s\n' "${key}" "${value}" >> "${regional_secrets}"
  else
    printf '%s=%s\n' "${key}" "${value}" >> "${regional_variables}"
  fi
done < "${regional_env}"
chmod 0600 "${regional_variables}" "${regional_secrets}"
bash "${ROOT}/scripts/release/compose-deployment-values.sh" \
  --variables-file "${regional_variables}" --secrets-file "${regional_secrets}" \
  --core-image "registry.example.test/midori/core:${tag_a}" \
  --control-image "registry.example.test/midori/control:${tag_a}" \
  --output "${test_root}/regional-composed.env" >/dev/null
if grep -q '^CONTROL_IMAGE=' "${test_root}/regional-composed.env"; then
  fail "regional Actions composition injected Control"
fi
bash "${HOST_DIR}/render-quadlets.sh" --env-file "${test_root}/regional-composed.env" --output-dir "${test_root}/regional-render" --runtime-dir "${runtime_dir}" >/dev/null
[[ -f "${test_root}/regional-render/rootless/midorivpn-core.container" ]] || fail "regional render lacks Core"
[[ ! -f "${test_root}/regional-render/rootless/midorivpn-postgres.container" ]] || fail "regional render contains PostgreSQL"
[[ ! -f "${test_root}/regional-render/rootless/midorivpn-control.container" ]] || fail "regional render contains Control"
cp "${regional_env}" "${test_root}/regional-secret.env"
printf 'CONTROL_DATA_ENCRYPTION_KEY=must-not-leave-principal\n' >> "${test_root}/regional-secret.env"
chmod 0600 "${test_root}/regional-secret.env"
if bash "${HOST_DIR}/render-quadlets.sh" --env-file "${test_root}/regional-secret.env" --output-dir "${test_root}/bad-regional" --runtime-dir "${runtime_dir}" >/dev/null 2>&1; then
  fail "regional renderer accepted a principal-only secret"
fi

bad_image_cases=(
  'registry.example.test/midori/core@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  'registry.example.test/midori/core:latest'
  'registry.example.test/midori/core:stable'
  'registry.example.test/midori/core'
)
bad_image_index=0
for bad_image in "${bad_image_cases[@]}"; do
  bad_image_index=$((bad_image_index + 1))
  bad_env="${test_root}/bad-image-${bad_image_index}.env"
  sed "s|CORE_IMAGE=registry.example.test/midori/core:${tag_a}|CORE_IMAGE=${bad_image}|" "${render_env}" > "${bad_env}"
  chmod 0600 "${bad_env}"
  if bash "${HOST_DIR}/render-quadlets.sh" --env-file "${bad_env}" --output-dir "${bad_env}.rendered" --runtime-dir "${runtime_dir}" >/dev/null 2>&1; then
    fail "renderer accepted invalid runtime image reference: ${bad_image}"
  fi
done

fake_bin="${test_root}/bin"
install -d -m 0700 "${fake_bin}"
cat > "${fake_bin}/curl" <<'EOF'
#!/usr/bin/env bash
set -eu
headers=''
body=''
write_out=false
while (($#)); do
  case "$1" in
    --dump-header) headers="$2"; shift 2 ;;
    --output) body="$2"; shift 2 ;;
    --write-out) write_out=true; shift 2 ;;
    --max-time) shift 2 ;;
    --fail|--silent|--show-error) shift ;;
    *) shift ;;
  esac
done
if [[ "${FAKE_EDGE_MODE:-good}" == html ]]; then
  printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-cache\r\n\r\n' > "${headers}"
  printf '<html>SPA</html>' > "${body}"
  [[ "${write_out}" == false ]] || printf 200
else
  printf 'HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\n\r\n' > "${headers}"
  : > "${body}"
  [[ "${write_out}" == false ]] || printf 204
fi
EOF
chmod 0700 "${fake_bin}/curl"
PATH="${fake_bin}:${PATH}" FAKE_EDGE_MODE=good bash "${HOST_DIR}/healthcheck.sh" --edge-url https://vpn.example.test/.well-known/midorivpn/edge-health --skip-units >/dev/null
if PATH="${fake_bin}:${PATH}" FAKE_EDGE_MODE=html bash "${HOST_DIR}/healthcheck.sh" --edge-url https://vpn.example.test/.well-known/midorivpn/edge-health --skip-units >/dev/null 2>&1; then
  fail "health gate accepted a SPA HTML 200"
fi

cat > "${fake_bin}/systemctl" <<'EOF'
#!/usr/bin/env sh
exit 0
EOF
chmod 0700 "${fake_bin}/systemctl"
extra_bundle="${test_root}/extra-bundle"
cp -a "${rendered}" "${extra_bundle}"
printf '[Container]\nImage=registry.example.test/evil:%s\n' "${tag_a}" > "${extra_bundle}/rootless/unmanifested.container"
chmod 0600 "${extra_bundle}/rootless/unmanifested.container"
if PATH="${fake_bin}:${PATH}" bash "${HOST_DIR}/install-quadlets.sh" --bundle "${extra_bundle}" --target-dir "${test_root}/bad-install/midorivpn" --backup-root "${test_root}/bad-backups" --no-start >/dev/null 2>&1; then
  fail "installer accepted an unmanifested unit"
fi
target="${test_root}/installed/midorivpn"
backup_root="${test_root}/install-backups"
install -d -m 0700 "${target}"
printf 'old\n' > "${target}/old.container"
chmod 0600 "${target}/old.container"
PATH="${fake_bin}:${PATH}" bash "${HOST_DIR}/install-quadlets.sh" --bundle "${rendered}" --target-dir "${target}" --backup-root "${backup_root}" --backup-record "${test_root}/unit-backup-record" --no-start >/dev/null
[[ -f "${target}/midorivpn-core.container" ]] || fail "installer did not place rendered units"
backup_dir="$(find "${backup_root}" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ "$(<"${test_root}/unit-backup-record")" == "${backup_dir}" ]] || fail "installer did not record the exact rollback snapshot"
[[ -f "${backup_dir}/previous/old.container" ]] || fail "installer did not retain the previous unit tree"
PATH="${fake_bin}:${PATH}" bash "${HOST_DIR}/rollback.sh" --backup-dir "${backup_dir}" --target-dir "${target}" >/dev/null
[[ -f "${target}/old.container" ]] || fail "rollback did not restore the prior unit tree"
[[ ! -f "${target}/midorivpn-core.container" ]] || fail "rollback retained the replacement unit tree"

printf 'Host deployment tests passed.\n'

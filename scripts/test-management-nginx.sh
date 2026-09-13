#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
configure_script="${ROOT}/deploy/host/configure-nginx.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/midorivpn-management-nginx-test.XXXXXX")"
cleanup() { rm -rf -- "${test_root}"; }
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

install -d -m 0700 "${test_root}/pki"
for name in ca.crt server.crt server.key; do
  printf 'fixture\n' > "${test_root}/pki/${name}"
done
chmod 0600 "${test_root}/pki/server.key"

write_env() {
  local destination="$1" profile="$2" address="$3"
  cat > "${destination}" <<EOF
DEPLOYMENT_PROFILE=${profile}
VPN_CORE_HOST_PORT=8085
NGINX_VHOST_PATH=/etc/nginx/conf.d/midorivpn-core.conf
MANAGEMENT_HOST_BIND=${address}
MANAGEMENT_HTTPS_PORT=8443
MANAGEMENT_TLS_CERT=${test_root}/pki/server.crt
MANAGEMENT_TLS_KEY=${test_root}/pki/server.key
MANAGEMENT_TLS_CA=${test_root}/pki/ca.crt
EOF
  chmod 0600 "${destination}"
}

principal_env="${test_root}/principal.env"
principal_output="${test_root}/principal-output"
write_env "${principal_env}" principal 10.254.240.1
bash "${configure_script}" --env-file "${principal_env}" --management-only \
  --render-only "${principal_output}" >/dev/null
[[ "$(find "${principal_output}" -maxdepth 1 -type f -printf '%f\n')" == management.conf ]] ||
  fail "management-only rendered unexpected files"
grep -Fq 'listen 10.254.240.1:8443 ssl;' "${principal_output}/management.conf" ||
  fail "principal listener bind is incorrect"
grep -Fq 'location ^~ /api/v1/node/' "${principal_output}/management.conf" ||
  fail "principal management route is missing"
if grep -Eq '__[A-Z0-9_]+__' "${principal_output}/management.conf"; then
  fail "principal management config contains placeholders"
fi

regional_env="${test_root}/regional.env"
regional_output="${test_root}/regional-output"
write_env "${regional_env}" core-node 10.254.240.2
bash "${configure_script}" --env-file "${regional_env}" --management-only \
  --render-only "${regional_output}" >/dev/null
grep -Fq 'listen 10.254.240.2:8443 ssl;' "${regional_output}/management.conf" ||
  fail "regional listener bind is incorrect"
for route in '/health' '/livez' '/readyz' '/api/v1/stats' '/api/v1/peers'; do
  grep -Fq "${route}" "${regional_output}/management.conf" ||
    fail "regional management route is missing: ${route}"
done
if grep -Fq '/api/v1/node/' "${regional_output}/management.conf"; then
  fail "regional listener exposes the principal node API"
fi

full_env="${test_root}/full.env"
cp -- "${principal_env}" "${full_env}"
cat >> "${full_env}" <<'EOF'
DOMAIN=vpn.example.test
ACME_WEBROOT=/var/www/acme
PROXY_ENABLED=false
CONTROL_HOST_PORT=5173
EOF
full_output="${test_root}/full-output"
bash "${configure_script}" --env-file "${full_env}" --render-only "${full_output}" >/dev/null
[[ "$(find "${full_output}" -maxdepth 1 -type f -printf '%f\n' | sort)" == $'management.conf\nvhost.conf' ]] ||
  fail "full mode no longer renders public and management configs"

if bash "${configure_script}" --env-file "${principal_env}" --management-only \
  --issue-certificate --render-only "${test_root}/invalid-output" >/dev/null 2>&1; then
  fail "management-only accepted certificate issuance"
fi

sed 's/MANAGEMENT_HOST_BIND=10.254.240.1/MANAGEMENT_HOST_BIND=203.0.113.1/' \
  "${principal_env}" > "${test_root}/public-address.env"
chmod 0600 "${test_root}/public-address.env"
if bash "${configure_script}" --env-file "${test_root}/public-address.env" --management-only \
  --render-only "${test_root}/public-address-output" >/dev/null 2>&1; then
  fail "management listener accepted a public bind address"
fi

printf 'Management Nginx tests passed.\n'

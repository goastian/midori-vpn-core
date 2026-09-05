#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHECK_DIR="$(mktemp -d "${ROOT_DIR}/tmp/observability-check.XXXXXX")"
CHECK_DIR_IN_CONTAINER="/workspace/${CHECK_DIR#"${ROOT_DIR}/"}"

cleanup() {
  rm -rf -- "${CHECK_DIR}"
}
trap cleanup EXIT

openssl req -x509 -newkey ed25519 -noenc -days 1 \
  -subj '/CN=midorivpn-observability-check' \
  -keyout "${CHECK_DIR}/prometheus-client.key" \
  -out "${CHECK_DIR}/prometheus-client.crt" >/dev/null 2>&1
chmod 0600 "${CHECK_DIR}/prometheus-client.key"
install -m 0644 "${CHECK_DIR}/prometheus-client.crt" "${CHECK_DIR}/observability-ca.crt"

sed \
  -e 's/__OBSERVABILITY_CLUSTER__/test-cluster/g' \
  -e 's/__CORE_NODE_NAME__/test-node/g' \
  -e 's/__VPN_CORE_METRICS_TARGET__/midori-control:8085/g' \
  -e "s|/etc/prometheus/mtls/ca.crt|${CHECK_DIR_IN_CONTAINER}/observability-ca.crt|g" \
  -e "s|/etc/prometheus/mtls/client.crt|${CHECK_DIR_IN_CONTAINER}/prometheus-client.crt|g" \
  -e "s|/etc/prometheus/mtls/client.key|${CHECK_DIR_IN_CONTAINER}/prometheus-client.key|g" \
  "${ROOT_DIR}/deploy/observability/prometheus.yml.template" >"${CHECK_DIR}/prometheus.yml"
chmod 0755 "${CHECK_DIR}"
chmod 0644 "${CHECK_DIR}/prometheus.yml"

cat >"${CHECK_DIR}/render.env" <<EOF
OBSERVABILITY_CONFIG_DIR=${CHECK_DIR}/rendered
OBSERVABILITY_CLUSTER=test-cluster
OBSERVABILITY_NETWORK=test-network
CORE_NODE_NAME=test-node
VPN_CORE_METRICS_TARGET=midori-control:8085
VPN_CORE_HOST_PORT=8085
PROMETHEUS_HOST_PORT=9090
GRAFANA_HOST_PORT=3000
PROMETHEUS_IMAGE=docker.io/prom/prometheus@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
GRAFANA_IMAGE=docker.io/grafana/grafana@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
GRAFANA_ADMIN_USER=test-admin
GRAFANA_ADMIN_PASSWORD=test-password-only
PROMETHEUS_MTLS_CA=${CHECK_DIR}/observability-ca.crt
PROMETHEUS_MTLS_CLIENT_CERT=${CHECK_DIR}/prometheus-client.crt
PROMETHEUS_MTLS_CLIENT_KEY=${CHECK_DIR}/prometheus-client.key
EOF
chmod 0600 "${CHECK_DIR}/render.env"
ENV_FILE="${CHECK_DIR}/render.env" bash "${ROOT_DIR}/scripts/render-observability.sh"
if rg -n '__[A-Z0-9_]+__' "${CHECK_DIR}/rendered"; then
  printf 'error: rendered observability configuration still has placeholders\n' >&2
  exit 1
fi
test "$(stat -c '%a' "${CHECK_DIR}/rendered/grafana.env")" = "600"
grep -qx 'GF_SECURITY_ADMIN_USER=test-admin' "${CHECK_DIR}/rendered/grafana.env"
grep -qx 'GF_SECURITY_ADMIN_PASSWORD=test-password-only' "${CHECK_DIR}/rendered/grafana.env"
test "$(stat -c '%a' "${CHECK_DIR}/rendered/prometheus.yml")" = "644"
test "$(stat -c '%a' "${CHECK_DIR}/rendered/grafana-datasource.yml")" = "644"
rg -q '^          cluster: test-cluster$' "${CHECK_DIR}/rendered/prometheus.yml"
rg -q '^          role: principal$' "${CHECK_DIR}/rendered/prometheus.yml"
rg -q '^  - job_name: midorivpn-regional-core$' "${CHECK_DIR}/rendered/prometheus.yml"
rg -q '^[[:space:]]+min_version: TLS13$' "${CHECK_DIR}/rendered/prometheus.yml"
rg -q '^User=0$' "${CHECK_DIR}/rendered/midorivpn-prometheus.container"
QUADLET_UNIT_DIRS="${CHECK_DIR}/rendered" /usr/libexec/podman/quadlet --user --dryrun >/dev/null

bash "${ROOT_DIR}/scripts/pod.sh" promtool check config "${CHECK_DIR#"${ROOT_DIR}"/}/prometheus.yml"
bash "${ROOT_DIR}/scripts/pod.sh" promtool check rules deploy/observability/alerts.yml
bash "${ROOT_DIR}/scripts/pod.sh" node -e \
  'const fs=require("fs"); const p="deploy/grafana/midori-vpn-dashboard.json"; const d=JSON.parse(fs.readFileSync(p,"utf8")); if (!d.uid || !Array.isArray(d.panels) || d.panels.length < 6) throw new Error("dashboard contract incomplete")'

rg -q 'location = /metrics' "${ROOT_DIR}/deploy/nginx/core-vhost.conf.template"
rg -q 'return 404;' "${ROOT_DIR}/deploy/nginx/core-vhost.conf.template"
if rg -n '^PublishPort=0\.0\.0\.0:' "${ROOT_DIR}/deploy/observability" --glob '*.container*'; then
  printf 'error: observability UI port is not loopback-only\n' >&2
  exit 1
fi
rg -q '^Network=test-network$' "${CHECK_DIR}/rendered/midorivpn-prometheus.container"
rg -q '^Network=test-network$' "${CHECK_DIR}/rendered/midorivpn-grafana.container"
rg -q '^Environment=GF_PLUGINS_PREINSTALL_AUTO_UPDATE=false$' "${CHECK_DIR}/rendered/midorivpn-grafana.container"
rg -q '/etc/prometheus/mtls/client.key:ro,z$' "${CHECK_DIR}/rendered/midorivpn-prometheus.container"
rg -Fq -- '--publish "${OBSERVABILITY_HOST_BIND}:${OBSERVABILITY_MTLS_PORT}:${OBSERVABILITY_MTLS_PORT}/tcp"' "${ROOT_DIR}/scripts/VPN/deploy-core-node.sh"
rg -Fq 'for name in PROMETHEUS_MTLS_CLIENT_CERT PROMETHEUS_MTLS_CLIENT_KEY; do' "${ROOT_DIR}/scripts/VPN/deploy-core-node.sh"
rg -Fq -- '--network "${OBSERVABILITY_NETWORK}"' "${ROOT_DIR}/scripts/deploy-pod.sh"
rg -Fq "readonly VERIFIED_POD_INFRA_IMAGE='registry.k8s.io/pause@sha256:e5b941ef8f71de54dc3a13398226c269ba217d06650a21bd3afcf9d890cf1f41'" "${ROOT_DIR}/scripts/deploy-pod.sh"
rg -Fq -- '--infra-image "${POD_INFRA_IMAGE}"' "${ROOT_DIR}/scripts/deploy-pod.sh"
rg -Fq -- '--infra-command /pause' "${ROOT_DIR}/scripts/deploy-pod.sh"
rg -Fq 'wait_principal_target' "${ROOT_DIR}/scripts/deploy-observability.sh"
rg -Fq 'prepare_prometheus_volume' "${ROOT_DIR}/scripts/deploy-observability.sh"
rg -Fq 'podman volume exists midorivpn-prometheus-data' "${ROOT_DIR}/scripts/deploy-observability.sh"
rg -Fq -- '--pull=never' "${ROOT_DIR}/scripts/deploy-observability.sh"
rg -Fq 'cp -a -- "${QUADLET_DIR}/${unit_name}" "${backup_dir}/${unit_name}"' "${ROOT_DIR}/scripts/deploy-observability.sh"
rg -Fq 'restored_observability=true' "${ROOT_DIR}/scripts/deploy-observability.sh"

printf 'Observability configuration is valid and remains private.\n'

#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"
# shellcheck source=deploy/host/lib/common.sh
source "${ROOT_DIR}/deploy/host/lib/common.sh"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_value() {
  local name="$1"
  [ -n "${!name:-}" ] || die "missing required environment variable: ${name}"
}

escape_sed() {
  printf '%s' "$1" | sed 's/[&|\\]/\\&/g'
}

write_env_file_value() {
  local value="$1"
  [[ "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] || die "Grafana credentials must be single-line values"
  printf '%s' "${value}"
}

render() {
  local source="$1"
  local render_destination="$2"
  sed \
    -e "s|__OBSERVABILITY_CLUSTER__|$(escape_sed "${OBSERVABILITY_CLUSTER}")|g" \
    -e "s|__OBSERVABILITY_NETWORK__|$(escape_sed "${OBSERVABILITY_NETWORK}")|g" \
    -e "s|__CORE_NODE_NAME__|$(escape_sed "${CORE_NODE_NAME}")|g" \
    -e "s|__VPN_CORE_METRICS_TARGET__|$(escape_sed "${VPN_CORE_METRICS_TARGET}")|g" \
    -e "s|__PROMETHEUS_HOST_PORT__|${PROMETHEUS_HOST_PORT}|g" \
    -e "s|__GRAFANA_HOST_PORT__|${GRAFANA_HOST_PORT}|g" \
    -e "s|__PROMETHEUS_IMAGE__|$(escape_sed "${PROMETHEUS_IMAGE}")|g" \
    -e "s|__GRAFANA_IMAGE__|$(escape_sed "${GRAFANA_IMAGE}")|g" \
    -e "s|__PROMETHEUS_MTLS_CA__|$(escape_sed "${PROMETHEUS_MTLS_CA}")|g" \
    -e "s|__PROMETHEUS_MTLS_CLIENT_CERT__|$(escape_sed "${PROMETHEUS_MTLS_CLIENT_CERT}")|g" \
    -e "s|__PROMETHEUS_MTLS_CLIENT_KEY__|$(escape_sed "${PROMETHEUS_MTLS_CLIENT_KEY}")|g" \
    -e "s|__OBSERVABILITY_CONFIG_DIR__|$(escape_sed "${output_dir}")|g" \
    "${source}" >"${render_destination}"
  chmod 0644 "${render_destination}"
}

[ -f "${ENV_FILE}" ] || die "environment file not found: ${ENV_FILE}"
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

for name in \
  OBSERVABILITY_CONFIG_DIR OBSERVABILITY_CLUSTER OBSERVABILITY_NETWORK \
  CORE_NODE_NAME VPN_CORE_METRICS_TARGET \
  PROMETHEUS_HOST_PORT GRAFANA_HOST_PORT \
  PROMETHEUS_IMAGE GRAFANA_IMAGE GRAFANA_ADMIN_USER GRAFANA_ADMIN_PASSWORD \
  PROMETHEUS_MTLS_CA PROMETHEUS_MTLS_CLIENT_CERT PROMETHEUS_MTLS_CLIENT_KEY; do
  require_value "${name}"
done

[[ "${OBSERVABILITY_CLUSTER}" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "OBSERVABILITY_CLUSTER must be a lowercase DNS label"
[[ "${OBSERVABILITY_NETWORK}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$ ]] || die "OBSERVABILITY_NETWORK must be a Podman network name"
[[ "${CORE_NODE_NAME}" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "CORE_NODE_NAME must be a lowercase DNS label"
[[ "${VPN_CORE_METRICS_TARGET}" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}:[0-9]+$ ]] || die "VPN_CORE_METRICS_TARGET must be a network DNS name and port"
[[ "${GRAFANA_ADMIN_USER}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$ ]] || die "GRAFANA_ADMIN_USER contains unsupported characters"
for port_name in PROMETHEUS_HOST_PORT GRAFANA_HOST_PORT; do
  port_value="${!port_name}"
  if [[ ! "${port_value}" =~ ^[0-9]+$ ]] || ((port_value < 1 || port_value > 65535)); then
    die "${port_name} must be a valid TCP port"
  fi
done
host_validate_versioned_image "${PROMETHEUS_IMAGE}" PROMETHEUS_IMAGE
host_validate_versioned_image "${GRAFANA_IMAGE}" GRAFANA_IMAGE
(( ${#GRAFANA_ADMIN_PASSWORD} >= 16 )) || die "GRAFANA_ADMIN_PASSWORD must contain at least 16 characters"
for tls_path_name in PROMETHEUS_MTLS_CA PROMETHEUS_MTLS_CLIENT_CERT PROMETHEUS_MTLS_CLIENT_KEY; do
  tls_path="${!tls_path_name}"
  [[ "${tls_path}" = /* && -f "${tls_path}" && ! -L "${tls_path}" ]] || die "${tls_path_name} must be an absolute regular file"
done
[[ "$(stat -c '%a' "${PROMETHEUS_MTLS_CLIENT_KEY}")" == "600" ]] || die "PROMETHEUS_MTLS_CLIENT_KEY must have mode 0600"

output_dir="${1:-${OBSERVABILITY_CONFIG_DIR}}"
[[ "${output_dir}" = /* ]] || die "observability output directory must be absolute"
install -d -m 0700 "${output_dir}"

render "${ROOT_DIR}/deploy/observability/prometheus.yml.template" "${output_dir}/prometheus.yml"
render "${ROOT_DIR}/deploy/observability/grafana-datasource.yml.template" "${output_dir}/grafana-datasource.yml"
render "${ROOT_DIR}/deploy/observability/midorivpn-prometheus.container.template" "${output_dir}/midorivpn-prometheus.container"
render "${ROOT_DIR}/deploy/observability/midorivpn-grafana.container.template" "${output_dir}/midorivpn-grafana.container"
install -m 0644 "${ROOT_DIR}/deploy/observability/alerts.yml" "${output_dir}/alerts.yml"
install -m 0644 "${ROOT_DIR}/deploy/observability/grafana-dashboard-provider.yml" "${output_dir}/grafana-dashboard-provider.yml"
install -m 0644 "${ROOT_DIR}/deploy/grafana/midori-vpn-dashboard.json" "${output_dir}/midori-vpn-dashboard.json"
install -m 0644 "${ROOT_DIR}/deploy/observability/midorivpn-prometheus-data.volume" "${output_dir}/midorivpn-prometheus-data.volume"
install -m 0644 "${ROOT_DIR}/deploy/observability/midorivpn-grafana-data.volume" "${output_dir}/midorivpn-grafana-data.volume"

{
  printf 'GF_SECURITY_ADMIN_USER=%s\n' "$(write_env_file_value "${GRAFANA_ADMIN_USER}")"
  printf 'GF_SECURITY_ADMIN_PASSWORD=%s\n' "$(write_env_file_value "${GRAFANA_ADMIN_PASSWORD}")"
} >"${output_dir}/grafana.env"
chmod 0600 "${output_dir}/grafana.env"

printf 'Rendered private observability configuration in %s\n' "${output_dir}"

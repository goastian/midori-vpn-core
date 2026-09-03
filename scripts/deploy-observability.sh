#!/usr/bin/env bash
set -Eeuo pipefail

: "${OBSERVABILITY_CONFIG_DIR:?OBSERVABILITY_CONFIG_DIR is required}"
: "${QUADLET_DIR:?QUADLET_DIR is required}"
: "${CORE_IMAGE:?CORE_IMAGE is required}"

CORE_HEALTH_URL="${CORE_HEALTH_URL:-http://127.0.0.1:8085/readyz}"
PROMETHEUS_HEALTH_URL="${PROMETHEUS_HEALTH_URL:-http://127.0.0.1:9090/-/ready}"
GRAFANA_HEALTH_URL="${GRAFANA_HEALTH_URL:-http://127.0.0.1:3000/api/health}"
GRAFANA_STARTUP_ATTEMPTS="${GRAFANA_STARTUP_ATTEMPTS:-900}"
core_unit="${QUADLET_DIR}/control-api.container"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="${HOME}/backups/midorivpn-observability-${timestamp}"
core_changed=false

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

wait_url() {
  local url="$1"
  local label="$2"
  local attempts="${3:-60}"
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if curl --fail --silent --show-error --max-time 3 "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  printf 'error: %s did not become healthy: %s\n' "${label}" "${url}" >&2
  return 1
}

wait_principal_target() {
  local attempts="${1:-90}" response
  local query_url="http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22midorivpn-principal-core%22%7D"
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    response="$(curl --fail --silent --show-error --max-time 3 "${query_url}" 2>/dev/null || true)"
    if grep -Eq '"value":\[[^]]+,"1"\]' <<<"${response}"; then
      return 0
    fi
    sleep 1
  done
  printf 'error: principal Core did not become an authenticated Prometheus target\n' >&2
  return 1
}

rollback() {
  local status="$1"
  trap - ERR
  printf 'Deployment failed; restoring the prior Core Quadlet.\n' >&2
  systemctl --user stop midorivpn-grafana.service midorivpn-prometheus.service >/dev/null 2>&1 || true
  rm -f -- \
    "${QUADLET_DIR}/midorivpn-grafana.container" \
    "${QUADLET_DIR}/midorivpn-prometheus.container" \
    "${QUADLET_DIR}/midorivpn-grafana-data.volume" \
    "${QUADLET_DIR}/midorivpn-prometheus-data.volume"
  if [[ "${core_changed}" = true ]]; then
    cp -a -- "${backup_dir}/control-api.container" "${core_unit}"
  fi
  systemctl --user daemon-reload
  if [[ "${core_changed}" = true ]]; then
    systemctl --user restart control-api.service
  fi
  exit "${status}"
}

[[ "${OBSERVABILITY_CONFIG_DIR}" = /* && "${QUADLET_DIR}" = /* ]] || die "configuration paths must be absolute"
[[ "${CORE_IMAGE}" == localhost/* ]] || die "CORE_IMAGE must be a verified local staging image"
if [[ ! "${GRAFANA_STARTUP_ATTEMPTS}" =~ ^[0-9]+$ ]] || ((GRAFANA_STARTUP_ATTEMPTS < 1)); then
  die "GRAFANA_STARTUP_ATTEMPTS must be a positive integer"
fi
[[ -f "${core_unit}" ]] || die "Core Quadlet not found: ${core_unit}"
podman image exists "${CORE_IMAGE}" || die "Core image is not loaded: ${CORE_IMAGE}"

for file in \
  prometheus.yml alerts.yml grafana.env grafana-datasource.yml \
  grafana-dashboard-provider.yml midori-vpn-dashboard.json \
  midorivpn-prometheus.container midorivpn-grafana.container \
  midorivpn-prometheus-data.volume midorivpn-grafana-data.volume; do
  [[ -f "${OBSERVABILITY_CONFIG_DIR}/${file}" ]] || die "missing rendered file: ${file}"
done

install -d -m 0700 "${backup_dir}"
cp -a -- "${core_unit}" "${backup_dir}/control-api.container"
trap 'rollback $?' ERR

temporary_unit="$(mktemp "${core_unit}.XXXXXX")"
awk -v image="${CORE_IMAGE}" '
  /^Image=/ { print "Image=" image; image_written=1; next }
  { print }
  END { if (!image_written) exit 1 }
' "${core_unit}" >"${temporary_unit}"
chmod --reference="${core_unit}" "${temporary_unit}"
if cmp --silent "${temporary_unit}" "${core_unit}"; then
  rm -f -- "${temporary_unit}"
else
  mv -- "${temporary_unit}" "${core_unit}"
  core_changed=true
fi

install -m 0644 \
  "${OBSERVABILITY_CONFIG_DIR}/midorivpn-prometheus.container" \
  "${OBSERVABILITY_CONFIG_DIR}/midorivpn-grafana.container" \
  "${OBSERVABILITY_CONFIG_DIR}/midorivpn-prometheus-data.volume" \
  "${OBSERVABILITY_CONFIG_DIR}/midorivpn-grafana-data.volume" \
  "${QUADLET_DIR}/"

systemctl --user daemon-reload
if [[ "${core_changed}" = true ]]; then
  systemctl --user restart control-api.service
fi
wait_url "${CORE_HEALTH_URL}" "Core"

systemctl --user restart midorivpn-prometheus.service
wait_url "${PROMETHEUS_HEALTH_URL}" "Prometheus"
wait_principal_target
systemctl --user restart midorivpn-grafana.service
wait_url "${GRAFANA_HEALTH_URL}" "Grafana" "${GRAFANA_STARTUP_ATTEMPTS}"

trap - ERR
printf 'Observability deployment is healthy. Backup: %s\n' "${backup_dir}"

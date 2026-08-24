#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_value() {
  local name="$1"
  [ -n "${!name:-}" ] || die "missing required environment variable: ${name}"
}

[ "$(id -u)" -ne 0 ] || die "run as the dedicated rootless Podman user"

for name in MASQUE_SERVER_ID MASQUE_URI_TEMPLATE MASQUE_TLS_CERT MASQUE_TLS_KEY; do
  require_value "${name}"
done

QUADLET_DIR="${QUADLET_DIR:-${HOME}/.config/containers/systemd/midori-control}"
ENV_FILE="${ENV_FILE:-${QUADLET_DIR}/midori-control.env}"
API_QUADLET="${API_QUADLET:-${QUADLET_DIR}/control-api.container}"
POD_QUADLET="${POD_QUADLET:-${QUADLET_DIR}/midori-control.pod}"
MASQUE_PORT="${MASQUE_PORT:-443}"
MASQUE_HOST_PORT="${MASQUE_HOST_PORT:-8443}"
MASQUE_MAX_CLIENTS="${MASQUE_MAX_CLIENTS:-100}"
LETSENCRYPT_LIVE_DIR="${LETSENCRYPT_LIVE_DIR:-/etc/letsencrypt/live}"
LETSENCRYPT_ARCHIVE_DIR="${LETSENCRYPT_ARCHIVE_DIR:-/etc/letsencrypt/archive}"

for file in "${ENV_FILE}" "${API_QUADLET}" "${POD_QUADLET}" "${MASQUE_TLS_CERT}" "${MASQUE_TLS_KEY}"; do
  [ -r "${file}" ] || die "required file is not readable: ${file}"
done
[[ "${MASQUE_PORT}" =~ ^[0-9]+$ ]] && [ "${MASQUE_PORT}" -ge 1 ] && [ "${MASQUE_PORT}" -le 65535 ] || die "invalid MASQUE_PORT"
[[ "${MASQUE_HOST_PORT}" =~ ^[0-9]+$ ]] && [ "${MASQUE_HOST_PORT}" -ge 1024 ] && [ "${MASQUE_HOST_PORT}" -le 65535 ] || die "MASQUE_HOST_PORT must be an unprivileged port"
[[ "${MASQUE_MAX_CLIENTS}" =~ ^[0-9]+$ ]] && [ "${MASQUE_MAX_CLIENTS}" -ge 1 ] || die "invalid MASQUE_MAX_CLIENTS"

backup_dir="${QUADLET_DIR}/backups/masque-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${backup_dir}"
cp -a "${ENV_FILE}" "${API_QUADLET}" "${POD_QUADLET}" "${backup_dir}/"

upsert_env() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
  awk -v key="${key}" -v value="${value}" '
    BEGIN { found = 0 }
    index($0, key "=") == 1 { print key "=" value; found = 1; next }
    { print }
    END { if (!found) print key "=" value }
  ' "${ENV_FILE}" >"${tmp}"
  chmod 0600 "${tmp}"
  mv "${tmp}" "${ENV_FILE}"
}

upsert_env MASQUE_ENABLED true
upsert_env MASQUE_PORT "${MASQUE_PORT}"
upsert_env MASQUE_TLS_CERT "${MASQUE_TLS_CERT}"
upsert_env MASQUE_TLS_KEY "${MASQUE_TLS_KEY}"
upsert_env MASQUE_URI_TEMPLATE "${MASQUE_URI_TEMPLATE}"
upsert_env MASQUE_SERVER_ID "${MASQUE_SERVER_ID}"
upsert_env MASQUE_MAX_CLIENTS "${MASQUE_MAX_CLIENTS}"

tmp_api="$(mktemp "${API_QUADLET}.XXXXXX")"
awk -v live="${LETSENCRYPT_LIVE_DIR}" -v archive="${LETSENCRYPT_ARCHIVE_DIR}" '
  /^Volume=\/etc\/letsencrypt\/(live|archive):/ { next }
  /^\[Service\]$/ && !inserted {
    print "Volume=" live ":/etc/letsencrypt/live:ro"
    print "Volume=" archive ":/etc/letsencrypt/archive:ro"
    inserted = 1
  }
  { print }
' "${API_QUADLET}" >"${tmp_api}"
chmod --reference="${API_QUADLET}" "${tmp_api}"
mv "${tmp_api}" "${API_QUADLET}"

tmp_pod="$(mktemp "${POD_QUADLET}.XXXXXX")"
awk -v mapping="${MASQUE_HOST_PORT}:${MASQUE_PORT}/udp" -v container_port="${MASQUE_PORT}" '
  /^PublishPort=[0-9]+:[0-9]+\/udp$/ && $0 ~ (":" container_port "/udp$") { next }
  /^\[Service\]$/ && !inserted { print "PublishPort=" mapping; inserted = 1 }
  { print }
' "${POD_QUADLET}" >"${tmp_pod}"
chmod --reference="${POD_QUADLET}" "${tmp_pod}"
mv "${tmp_pod}" "${POD_QUADLET}"

systemctl --user daemon-reload
systemctl --user restart midori-control.service
systemctl --user start control-postgres.service control-redis.service control-api.service control-web.service

for unit in midori-control.service control-postgres.service control-redis.service control-api.service control-web.service; do
  if ! systemctl --user is-active --quiet "${unit}"; then
    printf 'error: %s failed; restoring Quadlet files from %s\n' "${unit}" "${backup_dir}" >&2
    cp -a "${backup_dir}/midori-control.env" "${ENV_FILE}"
    cp -a "${backup_dir}/control-api.container" "${API_QUADLET}"
    cp -a "${backup_dir}/midori-control.pod" "${POD_QUADLET}"
    systemctl --user daemon-reload
    systemctl --user restart midori-control.service || true
    systemctl --user start control-postgres.service control-redis.service control-api.service control-web.service || true
    exit 1
  fi
done

printf 'MASQUE Quadlet configuration applied; backup: %s\n' "${backup_dir}"

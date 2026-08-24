#!/usr/bin/env bash
set -Eeuo pipefail

PODMAN_USER="${MIDORI_PODMAN_USER:-wedc}"
EXPECTED_LINEAGE="${MIDORI_CERT_LINEAGE:?MIDORI_CERT_LINEAGE must identify the certificate lineage}"
SERVICE="${MIDORI_CORE_SERVICE:-control-api.service}"

if [ -n "${RENEWED_LINEAGE:-}" ] && [ "${RENEWED_LINEAGE}" != "${EXPECTED_LINEAGE}" ]; then
  exit 0
fi

uid="$(id -u "${PODMAN_USER}")"
runtime_dir="/run/user/${uid}"
[ -S "${runtime_dir}/bus" ] || {
  printf 'error: user service manager is unavailable for %s\n' "${PODMAN_USER}" >&2
  exit 1
}

runuser -u "${PODMAN_USER}" -- env XDG_RUNTIME_DIR="${runtime_dir}" \
  systemctl --user restart "${SERVICE}"

runuser -u "${PODMAN_USER}" -- env XDG_RUNTIME_DIR="${runtime_dir}" \
  systemctl --user is-active --quiet "${SERVICE}"

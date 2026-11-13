#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -ne 0 ] || die "run as the dedicated rootless Podman user"

REDIS_IMAGE="${REDIS_IMAGE:-docker.io/library/redis:8.10.3-alpine}"
QUADLET_DIR="${QUADLET_DIR:-${HOME}/.config/containers/systemd/midori-control}"
REDIS_QUADLET="${REDIS_QUADLET:-${QUADLET_DIR}/control-redis.container}"
BACKUP_ROOT="${BACKUP_ROOT:-${HOME}/backups/midori-control}"
REDIS_VOLUME="${REDIS_VOLUME:-control-redisdata}"

[ -r "${REDIS_QUADLET}" ] || die "Redis Quadlet is not readable: ${REDIS_QUADLET}"
podman image exists "${REDIS_IMAGE}" || die "image must be pulled and inspected first: ${REDIS_IMAGE}"
podman exec control-redis sh -ceu 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli SAVE | grep -qx OK'

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="${BACKUP_ROOT}/redis-${stamp}"
mkdir -p "${backup_dir}"
chmod 0700 "${backup_dir}"
cp -a "${REDIS_QUADLET}" "${backup_dir}/control-redis.container"

systemctl --user stop control-redis.service
podman volume export "${REDIS_VOLUME}" >"${backup_dir}/${REDIS_VOLUME}.tar"
chmod 0600 "${backup_dir}/${REDIS_VOLUME}.tar"

tmp="$(mktemp "${REDIS_QUADLET}.XXXXXX")"
awk -v image="${REDIS_IMAGE}" '
  /^Image=/ { print "Image=" image; replaced = 1; next }
  { print }
  END { if (!replaced) exit 1 }
' "${REDIS_QUADLET}" >"${tmp}"
chmod --reference="${REDIS_QUADLET}" "${tmp}"
mv "${tmp}" "${REDIS_QUADLET}"

systemctl --user daemon-reload
if ! systemctl --user start control-redis.service; then
  cp -a "${backup_dir}/control-redis.container" "${REDIS_QUADLET}"
  systemctl --user daemon-reload
  systemctl --user start control-redis.service || true
  die "Redis 8 failed to start; the previous Quadlet was restored"
fi

for _ in {1..30}; do
  if podman exec control-redis sh -ceu 'REDISCLI_AUTH="$REDIS_PASSWORD" timeout 5 redis-cli PING | grep -qx PONG'; then
    break
  fi
  sleep 1
done
podman exec control-redis sh -ceu 'REDISCLI_AUTH="$REDIS_PASSWORD" timeout 5 redis-cli PING | grep -qx PONG'
podman exec control-redis redis-server --version
printf 'Redis upgrade completed; backup: %s\n' "${backup_dir}"

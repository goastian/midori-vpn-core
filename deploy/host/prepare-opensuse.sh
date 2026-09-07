#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

mode="check"
service_user="midorivpn"

usage() {
  printf 'usage: %s [--check|--apply] [--service-user USER]\n' "$0"
}

while (($#)); do
  case "$1" in
    --check) mode="check"; shift ;;
    --apply) mode="apply"; shift ;;
    --service-user) service_user="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

[[ "${service_user}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || host_die "invalid service user"
host_require_regular_file /etc/os-release
# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
  opensuse-tumbleweed|opensuse-leap|opensuse) ;;
  *) host_die "this preparer supports openSUSE only; detected ${ID:-unknown}" ;;
esac

packages=(
  podman curl jq openssl nginx firewalld policycoreutils-python-utils
  fuse-overlayfs slirp4netns
)

certbot_has_nginx_plugin() {
  command -v certbot >/dev/null 2>&1 &&
    certbot plugins 2>/dev/null | grep -Eq '^[[:space:]]*\* nginx[[:space:]]*$'
}

if ! certbot_has_nginx_plugin; then
  case "${ID:-}" in
    opensuse-tumbleweed)
      packages+=(python313-certbot python313-certbot-nginx)
      ;;
    opensuse-leap|opensuse)
      packages+=(python3-certbot python3-certbot-nginx)
      ;;
  esac
fi

quadlet_is_available() {
  [[ -x /usr/libexec/podman/quadlet ||
     -x /usr/lib/podman/quadlet ||
     -x /usr/lib/systemd/system-generators/podman-system-generator ]]
}

has_subid_range() {
  local file="$1" user="$2"
  [[ -f "${file}" ]] || return 1
  awk -F: -v user="${user}" '
    $1 == user && $3 ~ /^[0-9]+$/ && $3 >= 65536 { found = 1 }
    END { exit(found ? 0 : 1) }
  ' "${file}"
}

verify_service_user() {
  local user="$1" user_uid
  getent passwd "${user}" >/dev/null || host_die "service user does not exist: ${user}"
  user_uid="$(id -u "${user}")"
  [[ "${user_uid}" != 0 ]] || host_die "service user must not be root"
  has_subid_range /etc/subuid "${user}" || host_die "service user lacks a subordinate UID range of at least 65536: ${user}"
  has_subid_range /etc/subgid "${user}" || host_die "service user lacks a subordinate GID range of at least 65536: ${user}"
}

missing=()
for package in "${packages[@]}"; do
  rpm -q --quiet "${package}" || missing+=("${package}")
done

if [[ "${mode}" == check ]]; then
  if ((${#missing[@]})); then
    printf 'Missing packages:'
    printf ' %s' "${missing[@]}"
    printf '\n'
  fi
  verify_service_user "${service_user}"
  loginctl show-user "${service_user}" -p Linger --value 2>/dev/null | grep -qx yes || host_die "linger is not enabled for ${service_user}"
  ((${#missing[@]} == 0)) || exit 1
  certbot_has_nginx_plugin || host_die "certbot with the nginx plugin is not available"
  quadlet_is_available || host_die "Podman Quadlet is not available"
  host_info "openSUSE host prerequisites are ready for ${service_user}"
  exit 0
fi

[[ "$(id -u)" == 0 ]] || host_die "--apply must run through sudo or as root"
host_require_command zypper
if ((${#missing[@]})); then
  zypper --non-interactive install --no-recommends "${missing[@]}"
fi

if ! getent passwd "${service_user}" >/dev/null; then
  useradd --create-home --shell /bin/bash "${service_user}"
fi
verify_service_user "${service_user}"
service_home="$(getent passwd "${service_user}" | cut -d: -f6)"
service_group="$(id -gn "${service_user}")"
[[ "${service_home}" == /* && -d "${service_home}" ]] || host_die "service user has no usable home directory"
certbot_has_nginx_plugin || host_die "certbot with the nginx plugin is not available after package installation"
quadlet_is_available || host_die "Podman Quadlet is not available after package installation"

loginctl enable-linger "${service_user}"
install -d -m 0700 -o "${service_user}" -g "${service_group}" \
  "${service_home}/.config/containers/systemd/midorivpn" \
  "${service_home}/.local/state/midorivpn-deploy/backups" \
  "${service_home}/volume"
install -d -m 0700 /etc/midorivpn /etc/containers/systemd/midorivpn
install -d -m 0750 -o root -g "${service_group}" /run/midorivpn-health

systemctl enable --now firewalld.service nginx.service
host_info "openSUSE host prepared; firewall ports and TLS remain explicit deployment gates"

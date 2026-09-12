#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

mode=check
role=""
listen_port=""
endpoint=""
peer_public_key_file=""
preshared_key_file=""
public_zone=public
management_zone=midorivpn-mgmt
interface=mvpn-mgmt
state_dir=/etc/wireguard/mvpn-mgmt
config_path=/etc/wireguard/mvpn-mgmt.conf
ownership_record=/etc/wireguard/mvpn-mgmt/installed.env
management_port=8443
observability_port=9443

usage() {
  printf 'usage: %s --role principal|regional [--prepare|--apply|--check] [--listen-port PORT] [--endpoint IP:PORT] [--peer-public-key-file PATH] [--preshared-key-file PATH] [--public-zone ZONE]\n' "$0"
}

while (($#)); do
  case "$1" in
    --prepare) mode=prepare; shift ;;
    --apply) mode=apply; shift ;;
    --check) mode=check; shift ;;
    --role) role="${2:-}"; shift 2 ;;
    --listen-port) listen_port="${2:-}"; shift 2 ;;
    --endpoint) endpoint="${2:-}"; shift 2 ;;
    --peer-public-key-file) peer_public_key_file="${2:-}"; shift 2 ;;
    --preshared-key-file) preshared_key_file="${2:-}"; shift 2 ;;
    --public-zone) public_zone="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

[[ "${role}" == principal || "${role}" == regional ]] || { usage >&2; host_die "--role must be principal or regional"; }
[[ "${public_zone}" =~ ^[A-Za-z0-9_-]+$ ]] || host_die "invalid public firewalld zone"
[[ "$(id -u)" == 0 ]] || host_die "management WireGuard configuration requires sudo or root"
host_require_command wg

private_key_path="${state_dir}/private.key"
public_key_path="${state_dir}/public.key"
local_address=10.254.240.1
peer_address=10.254.240.2
if [[ "${role}" == regional ]]; then
  local_address=10.254.240.2
  peer_address=10.254.240.1
fi

valid_wg_key_file() {
  local path="$1" value
  host_require_regular_file "${path}"
  value="$(<"${path}")"
  [[ "${value}" =~ ^[A-Za-z0-9+/]{43}=$ ]] || host_die "invalid WireGuard key file: ${path}"
}

if [[ "${mode}" == prepare ]]; then
  [[ ! -e "${private_key_path}" && ! -e "${public_key_path}" ]] || host_die "management WireGuard identity already exists"
  install -d -m 0700 "${state_dir}"
  wg genkey > "${private_key_path}"
  wg pubkey < "${private_key_path}" > "${public_key_path}"
  chmod 0600 "${private_key_path}"
  chmod 0644 "${public_key_path}"
  if [[ "${role}" == principal ]]; then
    [[ ! -e "${state_dir}/preshared.key" ]] || host_die "management preshared key already exists"
    wg genpsk > "${state_dir}/preshared.key"
    chmod 0600 "${state_dir}/preshared.key"
  fi
  host_info "Management WireGuard identity created. Share only ${public_key_path}."
  [[ "${role}" != principal ]] || host_info "Transfer ${state_dir}/preshared.key once through an authenticated encrypted channel; never paste it into logs or Actions variables."
  exit 0
fi

host_require_command firewall-cmd
host_require_command systemctl
valid_wg_key_file "${private_key_path}"

if [[ "${mode}" == check ]]; then
  systemctl is-active --quiet "wg-quick@${interface}.service" || host_die "${interface} is not active"
  ip -4 address show dev "${interface}" | grep -Fq "inet ${local_address}/32" || host_die "${interface} lacks ${local_address}/32"
  latest_handshake="$(wg show "${interface}" latest-handshakes | awk 'NR == 1 { print $2 }')"
  [[ "${latest_handshake}" =~ ^[0-9]+$ && "${latest_handshake}" -gt 0 ]] || host_die "${interface} has no authenticated handshake"
  (( $(date +%s) - latest_handshake <= 180 )) || host_die "${interface} handshake is older than 180 seconds"
  ping -c 1 -W 3 "${peer_address}" >/dev/null || host_die "management peer ${peer_address} is unreachable"
  host_info "Management WireGuard is healthy: ${local_address}/32 -> ${peer_address}/32"
  exit 0
fi

host_validate_port "${listen_port}" listen-port 1024
[[ -n "${peer_public_key_file}" && -n "${preshared_key_file}" ]] || host_die "--peer-public-key-file and --preshared-key-file are required"
valid_wg_key_file "${peer_public_key_file}"
valid_wg_key_file "${preshared_key_file}"
if [[ "${role}" == principal ]]; then
  endpoint_ip="${endpoint%:*}"
  endpoint_port="${endpoint##*:}"
  [[ "${endpoint_ip}" != "${endpoint}" && "${endpoint_port}" == "${listen_port}" ]] || host_die "principal --endpoint must be a direct IPv4 address using --listen-port"
  host_validate_ipv4 "${endpoint_ip}" endpoint
else
  [[ -z "${endpoint}" ]] || host_die "regional role does not accept --endpoint"
fi

private_key="$(<"${private_key_path}")"
peer_public_key="$(<"${peer_public_key_file}")"
preshared_key="$(<"${preshared_key_file}")"
temporary_config="$(mktemp /etc/wireguard/.mvpn-mgmt.XXXXXX)"
cleanup() { rm -f -- "${temporary_config}"; }
trap cleanup EXIT
{
  printf '[Interface]\nAddress = %s/32\nMTU = 1380\nPrivateKey = %s\n' "${local_address}" "${private_key}"
  [[ "${role}" != regional ]] || printf 'ListenPort = %s\n' "${listen_port}"
  printf '\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n' "${peer_public_key}" "${preshared_key}" "${peer_address}"
  if [[ "${role}" == principal ]]; then
    printf 'Endpoint = %s\nPersistentKeepalive = 25\n' "${endpoint}"
  fi
} > "${temporary_config}"
chmod 0600 "${temporary_config}"

fresh_install=true
if [[ -e "${config_path}" || -e "${ownership_record}" ]]; then
  host_require_regular_file "${config_path}"
  host_require_regular_file "${ownership_record}"
  cmp -s "${temporary_config}" "${config_path}" || host_die "refusing to replace a different ${config_path}"
  grep -Fqx "role=${role}" "${ownership_record}" || host_die "existing management ownership role differs"
  grep -Fqx "listen_port=${listen_port}" "${ownership_record}" || host_die "existing management ownership port differs"
  grep -Fqx "public_zone=${public_zone}" "${ownership_record}" || host_die "existing management ownership zone differs"
  fresh_install=false
fi
if [[ "${fresh_install}" == true ]]; then
  firewall-cmd --permanent --get-zones | tr ' ' '\n' | grep -Fxq "${management_zone}" && host_die "firewalld zone ${management_zone} already exists"
  if [[ "${role}" == regional ]]; then
    firewall-cmd --permanent --zone="${public_zone}" --query-port="${listen_port}/udp" >/dev/null && host_die "management UDP port already exists in ${public_zone}"
  fi
fi

rollback_failed_apply() {
  set +e
  if [[ "${fresh_install}" == true ]]; then
    systemctl disable --now "wg-quick@${interface}.service" >/dev/null 2>&1
    rm -f -- "${config_path}" "${ownership_record}"
    firewall-cmd --permanent --zone="${management_zone}" --remove-interface="${interface}" >/dev/null 2>&1
    firewall-cmd --permanent --delete-zone="${management_zone}" >/dev/null 2>&1
    if [[ "${role}" == regional ]]; then
      firewall-cmd --permanent --zone="${public_zone}" --remove-port="${listen_port}/udp" >/dev/null 2>&1
    fi
    firewall-cmd --reload >/dev/null 2>&1
  fi
  host_die "management WireGuard apply failed; created configuration and firewall rules were removed"
}
trap rollback_failed_apply ERR

if [[ "${fresh_install}" == true ]]; then
  install -m 0600 "${temporary_config}" "${config_path}"
  printf 'role=%s\nlisten_port=%s\npublic_zone=%s\n' "${role}" "${listen_port}" "${public_zone}" > "${ownership_record}"
  chmod 0600 "${ownership_record}"
  firewall-cmd --permanent --new-zone="${management_zone}" >/dev/null
fi
firewall-cmd --permanent --zone="${management_zone}" --add-interface="${interface}" >/dev/null
firewall-cmd --permanent --zone="${management_zone}" --add-port="${management_port}/tcp" >/dev/null
if [[ "${role}" == regional ]]; then
  firewall-cmd --permanent --zone="${management_zone}" --add-port="${observability_port}/tcp" >/dev/null
  firewall-cmd --permanent --zone="${public_zone}" --add-port="${listen_port}/udp" >/dev/null
fi
firewall-cmd --reload >/dev/null
systemctl enable --now "wg-quick@${interface}.service"
trap - ERR
trap cleanup EXIT
rm -f -- "${temporary_config}"
host_info "Management WireGuard converged at ${local_address}/32. Run --check only after both peers are active."

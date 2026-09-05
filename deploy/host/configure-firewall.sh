#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

env_file=""
mode="check"
backup_root="/var/lib/midorivpn-deploy/firewall-backups"
backup_record=""

usage() {
  printf 'usage: %s --env-file PATH [--check|--apply] [--backup-root PATH] [--backup-record FILE]\n' "$0"
}

while (($#)); do
  case "$1" in
    --env-file) env_file="${2:-}"; shift 2 ;;
    --check) mode=check; shift ;;
    --apply) mode=apply; shift ;;
    --backup-root) backup_root="${2:-}"; shift 2 ;;
    --backup-record) backup_record="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

[[ "$(id -u)" == 0 ]] || host_die "firewall configuration requires sudo or root"
[[ -n "${env_file}" ]] || { usage >&2; host_die "--env-file is required"; }
host_require_command firewall-cmd
declare -A cfg=()
host_load_env "${env_file}" cfg
host_require_env cfg WG_PORT
zone="${cfg[FIREWALL_ZONE]:-public}"
[[ "${zone}" =~ ^[A-Za-z0-9_-]+$ ]] || host_die "FIREWALL_ZONE is invalid"
if [[ ! "${cfg[WG_PORT]}" =~ ^[0-9]+$ ]] || ((cfg[WG_PORT] < 1024 || cfg[WG_PORT] > 65535)); then
  host_die "WG_PORT must be an unprivileged UDP port"
fi

services=(http https)
ports=("${cfg[WG_PORT]}/udp")
forward_ports=()

for boolean_key in MASQUE_ENABLED PROXY_ENABLED; do
  value="${cfg[${boolean_key}]:-false}"
  [[ "${value}" == true || "${value}" == false ]] || host_die "${boolean_key} must be true or false"
done

if [[ "${cfg[PROXY_ENABLED]:-false}" == true ]]; then
  host_require_env cfg PROXY_PORT
  if [[ ! "${cfg[PROXY_PORT]}" =~ ^[0-9]+$ ]] || ((cfg[PROXY_PORT] < 1 || cfg[PROXY_PORT] > 65535)); then
    host_die "PROXY_PORT is invalid"
  fi
  ports+=("${cfg[PROXY_PORT]}/tcp")
fi

if [[ "${cfg[MASQUE_ENABLED]:-false}" == true ]]; then
  host_require_env cfg MASQUE_PORT
  host_require_env cfg MASQUE_HOST_PORT
  if [[ ! "${cfg[MASQUE_PORT]}" =~ ^[0-9]+$ ]] || ((cfg[MASQUE_PORT] < 1 || cfg[MASQUE_PORT] > 65535)); then
    host_die "MASQUE_PORT is invalid"
  fi
  if [[ ! "${cfg[MASQUE_HOST_PORT]}" =~ ^[0-9]+$ ]] || ((cfg[MASQUE_HOST_PORT] < 1024 || cfg[MASQUE_HOST_PORT] > 65535)); then
    host_die "MASQUE_HOST_PORT must be unprivileged"
  fi
  forward_ports+=("port=${cfg[MASQUE_PORT]}:proto=udp:toport=${cfg[MASQUE_HOST_PORT]}")
fi

missing=()
for service in "${services[@]}"; do
  firewall-cmd --permanent --zone="${zone}" --query-service="${service}" >/dev/null || missing+=("service:${service}")
done
for port in "${ports[@]}"; do
  firewall-cmd --permanent --zone="${zone}" --query-port="${port}" >/dev/null || missing+=("port:${port}")
done
for forward_port in "${forward_ports[@]}"; do
  firewall-cmd --permanent --zone="${zone}" --query-forward-port="${forward_port}" >/dev/null || missing+=("forward:${forward_port}")
done

if [[ "${mode}" == check ]]; then
  if ((${#missing[@]})); then
    printf 'Missing firewalld rules in zone %s:\n' "${zone}"
    printf '  %s\n' "${missing[@]}"
    exit 1
  fi
  host_info "firewalld ingress is ready in zone ${zone}"
  exit 0
fi

install -d -m 0700 -- "${backup_root}"
backup_dir="$(mktemp -d "${backup_root}/$(host_timestamp).XXXXXX")"
if [[ -n "${backup_record}" ]]; then
  [[ "${backup_record}" == /* ]] || host_die "--backup-record must be absolute"
  install -d -m 0700 -- "$(dirname -- "${backup_record}")"
  printf '%s\n' "${backup_dir}" > "${backup_record}"
  chmod 0600 "${backup_record}"
fi
firewall-cmd --permanent --zone="${zone}" --list-all > "${backup_dir}/zone-before.txt"
chmod 0600 "${backup_dir}/zone-before.txt"
{
  printf 'zone=%s\n' "${zone}"
  printf 'service=%s\n' "${services[@]}"
  printf 'port=%s\n' "${ports[@]}"
  printf 'forward=%s\n' "${forward_ports[@]}"
} > "${backup_dir}/declared-rules.txt"
chmod 0600 "${backup_dir}/declared-rules.txt"
added_services=()
added_ports=()
added_forwards=()
rollback_firewall() {
  set +e
  local item
  for item in "${added_services[@]}"; do
    firewall-cmd --permanent --zone="${zone}" --remove-service="${item}" >/dev/null
  done
  for item in "${added_ports[@]}"; do
    firewall-cmd --permanent --zone="${zone}" --remove-port="${item}" >/dev/null
  done
  for item in "${added_forwards[@]}"; do
    firewall-cmd --permanent --zone="${zone}" --remove-forward-port="${item}" >/dev/null
  done
  firewall-cmd --reload >/dev/null
  host_die "firewalld update failed; rules added by this run were removed"
}
trap rollback_firewall ERR

for service in "${services[@]}"; do
  if ! firewall-cmd --permanent --zone="${zone}" --query-service="${service}" >/dev/null; then
    firewall-cmd --permanent --zone="${zone}" --add-service="${service}"
    added_services+=("${service}")
  fi
done
for port in "${ports[@]}"; do
  if ! firewall-cmd --permanent --zone="${zone}" --query-port="${port}" >/dev/null; then
    firewall-cmd --permanent --zone="${zone}" --add-port="${port}"
    added_ports+=("${port}")
  fi
done
for forward_port in "${forward_ports[@]}"; do
  if ! firewall-cmd --permanent --zone="${zone}" --query-forward-port="${forward_port}" >/dev/null; then
    firewall-cmd --permanent --zone="${zone}" --add-forward-port="${forward_port}"
    added_forwards+=("${forward_port}")
  fi
done
firewall-cmd --reload
: > "${backup_dir}/added-rules.tsv"
chmod 0600 "${backup_dir}/added-rules.tsv"
for item in "${added_services[@]}"; do printf 'service\t%s\n' "${item}" >> "${backup_dir}/added-rules.tsv"; done
for item in "${added_ports[@]}"; do printf 'port\t%s\n' "${item}" >> "${backup_dir}/added-rules.tsv"; done
for item in "${added_forwards[@]}"; do printf 'forward\t%s\n' "${item}" >> "${backup_dir}/added-rules.tsv"; done
trap - ERR
host_info "firewalld ingress applied in zone ${zone}; no database or administrative port was exposed"
host_info "firewalld pre-change snapshot: ${backup_dir}"

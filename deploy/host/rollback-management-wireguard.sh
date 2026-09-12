#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

role="${1:-}"
listen_port="${2:-}"
public_zone="${3:-public}"
interface=mvpn-mgmt
ownership_record=/etc/wireguard/mvpn-mgmt/installed.env

[[ "${role}" == principal || "${role}" == regional ]] || host_die "usage: $0 principal|regional LISTEN_PORT [PUBLIC_ZONE]"
host_validate_port "${listen_port}" listen-port 1024
[[ "${public_zone}" =~ ^[A-Za-z0-9_-]+$ ]] || host_die "invalid public firewalld zone"
[[ "$(id -u)" == 0 ]] || host_die "management WireGuard rollback requires sudo or root"
host_require_command firewall-cmd
host_require_command systemctl
host_require_regular_file "${ownership_record}"
grep -Fqx "role=${role}" "${ownership_record}" || host_die "rollback role does not match the installed overlay"
grep -Fqx "listen_port=${listen_port}" "${ownership_record}" || host_die "rollback port does not match the installed overlay"
grep -Fqx "public_zone=${public_zone}" "${ownership_record}" || host_die "rollback zone does not match the installed overlay"

systemctl disable --now "wg-quick@${interface}.service" >/dev/null 2>&1 || true
rm -f -- "/etc/wireguard/${interface}.conf"
if firewall-cmd --permanent --get-zones | tr ' ' '\n' | grep -Fxq midorivpn-management; then
  firewall-cmd --permanent --zone=midorivpn-management --remove-interface="${interface}" >/dev/null 2>&1 || true
  firewall-cmd --permanent --delete-zone=midorivpn-management >/dev/null
fi
if [[ "${role}" == regional ]]; then
  firewall-cmd --permanent --zone="${public_zone}" --remove-port="${listen_port}/udp" >/dev/null 2>&1 || true
fi
firewall-cmd --reload >/dev/null
rm -f -- "${ownership_record}"
host_info "Management WireGuard service, configuration and firewall rules were removed; cryptographic keys remain in /etc/wireguard/mvpn-mgmt."

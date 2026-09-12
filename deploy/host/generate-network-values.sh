#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

host_require_command openssl
host_require_command ss

udp_port_in_use() {
  local port="$1" sockets error_file status
  error_file="$(mktemp "${TMPDIR:-/tmp}/midorivpn-ss.XXXXXX")"
  set +e
  sockets="$(ss -H -lun 2>"${error_file}")"
  status=$?
  set -e
  if ((status != 0)) || [[ -s "${error_file}" ]]; then
    rm -f -- "${error_file}"
    host_die "could not inspect current UDP listeners"
  fi
  rm -f -- "${error_file}"
  awk '{ print $5 }' <<< "${sockets}" | grep -Eq "(^|:)${port}$"
}

random_high_port() {
  local candidate hex
  while :; do
    hex="$(openssl rand -hex 2)"
    candidate=$((49152 + 16#${hex} % 16384))
    udp_port_in_use "${candidate}" || { printf '%s\n' "${candidate}"; return; }
  done
}

management_port="$(random_high_port)"
customer_port="$(random_high_port)"
while [[ "${customer_port}" == "${management_port}" ]]; do
  customer_port="$(random_high_port)"
done
endpoint_label="$(openssl rand -hex 16)"

printf 'MANAGEMENT_WG_PORT=%s\n' "${management_port}"
printf 'WG_PORT=%s\n' "${customer_port}"
printf 'WG_ENDPOINT=%s.central.astian.org\n' "${endpoint_label}"
printf 'Keep these values in the production inventory. The DNS record must be DNS-only, never Cloudflare-proxied.\n' >&2

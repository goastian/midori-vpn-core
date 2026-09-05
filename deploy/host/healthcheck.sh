#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

edge_url=""
core_url=""
control_url=""
scope="rootless"
skip_units=false

usage() {
  printf 'usage: %s --edge-url URL [--core-url URL] [--control-url URL] [--scope rootless|rootful] [--skip-units]\n' "$0"
}

while (($#)); do
  case "$1" in
    --edge-url) edge_url="${2:-}"; shift 2 ;;
    --core-url) core_url="${2:-}"; shift 2 ;;
    --control-url) control_url="${2:-}"; shift 2 ;;
    --scope) scope="${2:-}"; shift 2 ;;
    --skip-units) skip_units=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

if [[ ! "${edge_url}" =~ ^https://[^/?#[:space:]@]+/\.well-known/midorivpn/edge-health$ && ! "${edge_url}" =~ ^http://127\.0\.0\.1:[0-9]+/\.well-known/midorivpn/edge-health$ ]]; then
  host_die "--edge-url must target the exact MidoriVPN edge-health path"
fi
host_require_command curl

if [[ "${skip_units}" == false ]]; then
  if [[ "${scope}" == rootless ]]; then
    systemctl_cmd=(systemctl --user)
  elif [[ "${scope}" == rootful ]]; then
    systemctl_cmd=(systemctl)
  else
    host_die "scope must be rootless or rootful"
  fi
  "${systemctl_cmd[@]}" is-active --quiet midorivpn-core.service || host_die "midorivpn-core.service is not active"
fi

check_success_url() {
  local label="$1" url="$2"
  [[ -n "${url}" ]] || return 0
  curl --fail --silent --show-error --max-time 10 --output /dev/null "${url}" || host_die "${label} health request failed"
}
check_success_url core "${core_url}"
check_success_url control "${control_url}"

headers="$(mktemp "${TMPDIR:-/tmp}/midorivpn-edge-headers.XXXXXX")"
body="$(mktemp "${TMPDIR:-/tmp}/midorivpn-edge-body.XXXXXX")"
cleanup() { rm -f -- "${headers}" "${body}"; }
trap cleanup EXIT
status="$(curl --silent --show-error --max-time 10 --dump-header "${headers}" --output "${body}" --write-out '%{http_code}' "${edge_url}")" || host_die "edge probe request failed"
[[ "${status}" == 204 ]] || host_die "edge probe must return 204, received ${status}"
[[ ! -s "${body}" ]] || host_die "edge probe response body must be empty"
grep -Eiq '^cache-control:[[:space:]]*no-store([[:space:]]|,|$)' "${headers}" || host_die "edge probe must return Cache-Control: no-store"
if grep -Eiq '^content-type:.*text/html' "${headers}"; then
  host_die "edge probe resolved to HTML instead of Core"
fi
host_info "MidoriVPN health gate passed, including exact edge-health semantics"

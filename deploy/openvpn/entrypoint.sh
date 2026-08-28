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

valid_ipv4() {
  local address="$1" octet
  [[ "${address}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<<"${address}"
  for octet in "${octets[@]}"; do
    [ "${octet}" -ge 0 ] && [ "${octet}" -le 255 ] || return 1
  done
}

sed_escape() {
  printf '%s' "$1" | sed 's/[&|]/\\&/g'
}

netmask_from_prefix() {
  local remaining="$1" index value output=""
  for index in 1 2 3 4; do
    if [ "${remaining}" -ge 8 ]; then
      value=255
      remaining=$((remaining - 8))
    elif [ "${remaining}" -le 0 ]; then
      value=0
    else
      value=$((256 - (1 << (8 - remaining))))
      remaining=0
    fi
    output+="${output:+.}${value}"
  done
  printf '%s' "${output}"
}

is_network_address() {
  local address="$1" mask="$2" index
  local -a address_octets mask_octets
  IFS=. read -r -a address_octets <<<"${address}"
  IFS=. read -r -a mask_octets <<<"${mask}"
  for index in 0 1 2 3; do
    [ $((10#${address_octets[index]} & 10#${mask_octets[index]})) -eq $((10#${address_octets[index]})) ] || return 1
  done
}

for name in OPENVPN_PORT OPENVPN_INTERFACE OPENVPN_NETWORK_CIDR OPENVPN_SERVER_NAME VPN_DNS VPN_CLIENT_CRL_URL; do
  require_value "${name}"
done
[[ "${OPENVPN_PORT}" =~ ^[0-9]+$ ]] && [ "${OPENVPN_PORT}" -ge 1 ] && [ "${OPENVPN_PORT}" -le 65535 ] || die "invalid OPENVPN_PORT"
[[ "${OPENVPN_INTERFACE}" =~ ^[A-Za-z0-9_-]{1,15}$ ]] || die "invalid OPENVPN_INTERFACE"
valid_ipv4 "${VPN_DNS}" || die "invalid VPN_DNS"
[[ "${OPENVPN_NETWORK_CIDR}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-9]|[12][0-9]|30)$ ]] || die "invalid OPENVPN_NETWORK_CIDR"
OPENVPN_NETWORK="${OPENVPN_NETWORK_CIDR%/*}"
OPENVPN_PREFIX="${OPENVPN_NETWORK_CIDR#*/}"
valid_ipv4 "${OPENVPN_NETWORK}" || die "invalid OPENVPN_NETWORK_CIDR address"
OPENVPN_NETMASK="$(netmask_from_prefix "${OPENVPN_PREFIX}")"
is_network_address "${OPENVPN_NETWORK}" "${OPENVPN_NETMASK}" || die "OPENVPN_NETWORK_CIDR must use the network address"
[[ "${VPN_CLIENT_CRL_URL}" == https://* ]] || die "VPN_CLIENT_CRL_URL must use https"
[[ "${OPENVPN_SERVER_NAME}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "invalid OPENVPN_SERVER_NAME"

OPENVPN_CA_CERT="${OPENVPN_CA_CERT:-/etc/midorivpn/pki/client-ca.pem}"
OPENVPN_GATEWAY_CERT="${OPENVPN_GATEWAY_CERT:-/etc/midorivpn/pki/gateway.crt}"
OPENVPN_GATEWAY_KEY="${OPENVPN_GATEWAY_KEY:-/etc/midorivpn/pki/gateway.key}"
OPENVPN_BINARY="${OPENVPN_BINARY:-/usr/sbin/openvpn}"
OPENVPN_HEALTH_BINARY="${OPENVPN_HEALTH_BINARY:-/usr/local/libexec/midorivpn-openvpn-health}"
OPENVPN_TEMPLATE="${OPENVPN_TEMPLATE:-/usr/share/midorivpn/openvpn/server.conf.template}"
OPENVPN_DEPLOYMENT_MODE="${OPENVPN_DEPLOYMENT_MODE:-rootful}"
OPENVPN_RUNTIME_DIR="/run/midorivpn-openvpn"
OPENVPN_HEALTH_FILE="/run/midorivpn-health/openvpn.json"
[[ "${OPENVPN_DEPLOYMENT_MODE}" == "rootful" || "${OPENVPN_DEPLOYMENT_MODE}" == "host" ]] || die "invalid OPENVPN_DEPLOYMENT_MODE"

for file in "${OPENVPN_CA_CERT}" "${OPENVPN_GATEWAY_CERT}" "${OPENVPN_GATEWAY_KEY}"; do
  [ -r "${file}" ] || die "required PKI file is not readable: ${file}"
done
openssl x509 -in "${OPENVPN_GATEWAY_CERT}" -noout -checkend 86400 >/dev/null || die "gateway certificate expires within 24 hours"
openssl verify -purpose sslserver -verify_hostname "${OPENVPN_SERVER_NAME}" -CAfile "${OPENVPN_CA_CERT}" "${OPENVPN_GATEWAY_CERT}" >/dev/null || die "gateway certificate verification failed"

install -d -m 0700 "${OPENVPN_RUNTIME_DIR}"
install -d -m 0755 /run/midorivpn-health
rm -f "${OPENVPN_HEALTH_FILE}"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 "${VPN_CLIENT_CRL_URL}" -o "${OPENVPN_RUNTIME_DIR}/client.crl.der"
openssl crl -inform DER -in "${OPENVPN_RUNTIME_DIR}/client.crl.der" -out "${OPENVPN_RUNTIME_DIR}/client.crl.next" -outform PEM || die "initial client CRL encoding is invalid"
openssl crl -in "${OPENVPN_RUNTIME_DIR}/client.crl.next" -CAfile "${OPENVPN_CA_CERT}" -noout -verify >/dev/null || die "initial client CRL verification failed"
chmod 0644 "${OPENVPN_RUNTIME_DIR}/client.crl.next"
mv "${OPENVPN_RUNTIME_DIR}/client.crl.next" "${OPENVPN_RUNTIME_DIR}/client.crl"
rm -f "${OPENVPN_RUNTIME_DIR}/client.crl.der"

sed \
  -e "s|__PORT__|$(sed_escape "${OPENVPN_PORT}")|g" \
  -e "s|__INTERFACE__|$(sed_escape "${OPENVPN_INTERFACE}")|g" \
  -e "s|__NETWORK__|$(sed_escape "${OPENVPN_NETWORK}")|g" \
  -e "s|__NETMASK__|$(sed_escape "${OPENVPN_NETMASK}")|g" \
  -e "s|__DNS__|$(sed_escape "${VPN_DNS}")|g" \
  -e "s|__CA_CERT__|$(sed_escape "${OPENVPN_CA_CERT}")|g" \
  -e "s|__GATEWAY_CERT__|$(sed_escape "${OPENVPN_GATEWAY_CERT}")|g" \
  -e "s|__GATEWAY_KEY__|$(sed_escape "${OPENVPN_GATEWAY_KEY}")|g" \
  "${OPENVPN_TEMPLATE}" >"${OPENVPN_RUNTIME_DIR}/server.conf"
chmod 0600 "${OPENVPN_RUNTIME_DIR}/server.conf"

[ "$(sysctl -n net.ipv4.ip_forward)" = "1" ] || die "host must have net.ipv4.ip_forward=1"
nft delete table ip midori_openvpn 2>/dev/null || true
nft add table ip midori_openvpn
nft 'add chain ip midori_openvpn postrouting { type nat hook postrouting priority srcnat; policy accept; }'
nft add rule ip midori_openvpn postrouting ip saddr "${OPENVPN_NETWORK_CIDR}" masquerade

refresh_crl() {
  while sleep 60; do
    if curl --fail --silent --show-error --proto '=https' --tlsv1.2 "${VPN_CLIENT_CRL_URL}" -o "${OPENVPN_RUNTIME_DIR}/client.crl.der" && \
      openssl crl -inform DER -in "${OPENVPN_RUNTIME_DIR}/client.crl.der" -out "${OPENVPN_RUNTIME_DIR}/client.crl.next" -outform PEM && \
      openssl crl -in "${OPENVPN_RUNTIME_DIR}/client.crl.next" -CAfile "${OPENVPN_CA_CERT}" -noout -verify >/dev/null; then
      chmod 0644 "${OPENVPN_RUNTIME_DIR}/client.crl.next"
      mv "${OPENVPN_RUNTIME_DIR}/client.crl.next" "${OPENVPN_RUNTIME_DIR}/client.crl"
    else
      rm -f "${OPENVPN_RUNTIME_DIR}/client.crl.der" "${OPENVPN_RUNTIME_DIR}/client.crl.next"
      printf 'warning: rejected client CRL refresh\n' >&2
    fi
    rm -f "${OPENVPN_RUNTIME_DIR}/client.crl.der"
  done
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  rm -f "${OPENVPN_HEALTH_FILE}"
  [ -z "${health_pid:-}" ] || kill "${health_pid}" 2>/dev/null || true
  [ -z "${refresh_pid:-}" ] || kill "${refresh_pid}" 2>/dev/null || true
  [ -z "${openvpn_pid:-}" ] || kill "${openvpn_pid}" 2>/dev/null || true
  wait 2>/dev/null || true
  nft delete table ip midori_openvpn 2>/dev/null || true
  exit "${status}"
}
trap cleanup EXIT INT TERM

export OPENVPN_MANAGEMENT_SOCKET="${OPENVPN_RUNTIME_DIR}/management.sock"
export OPENVPN_LOG_PATH="${OPENVPN_RUNTIME_DIR}/openvpn.log"
export OPENVPN_HEALTH_FILE
refresh_crl &
refresh_pid=$!
"${OPENVPN_BINARY}" --config "${OPENVPN_RUNTIME_DIR}/server.conf" &
openvpn_pid=$!
for _ in $(seq 1 100); do
  [ -S "${OPENVPN_MANAGEMENT_SOCKET}" ] && break
  kill -0 "${openvpn_pid}" 2>/dev/null || die "OpenVPN exited during startup"
  sleep 0.1
done
[ -S "${OPENVPN_MANAGEMENT_SOCKET}" ] || die "OpenVPN management socket was not created"
"${OPENVPN_HEALTH_BINARY}" &
health_pid=$!
while kill -0 "${openvpn_pid}" 2>/dev/null && kill -0 "${health_pid}" 2>/dev/null && kill -0 "${refresh_pid}" 2>/dev/null; do
  sleep 1
done
if kill -0 "${openvpn_pid}" 2>/dev/null; then
  die "OpenVPN gateway helper exited unexpectedly"
fi
wait "${openvpn_pid}"

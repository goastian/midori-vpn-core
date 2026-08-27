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

for name in OPENVPN_PORT OPENVPN_INTERFACE OPENVPN_NETWORK_CIDR VPN_DNS VPN_CLIENT_CRL_URL; do
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

for file in /run/secrets/client-ca.pem /run/secrets/gateway.crt /run/secrets/gateway.key; do
  [ -r "${file}" ] || die "required PKI file is not readable: ${file}"
done
openssl x509 -in /run/secrets/gateway.crt -noout -checkend 86400 >/dev/null || die "gateway certificate expires within 24 hours"
openssl verify -purpose sslserver -CAfile /run/secrets/client-ca.pem /run/secrets/gateway.crt >/dev/null || die "gateway certificate verification failed"

install -d -m 0700 /run/openvpn
curl --fail --silent --show-error --proto '=https' --tlsv1.2 "${VPN_CLIENT_CRL_URL}" -o /run/openvpn/client.crl.der
openssl crl -inform DER -in /run/openvpn/client.crl.der -out /run/openvpn/client.crl.next -outform PEM || die "initial client CRL encoding is invalid"
openssl crl -in /run/openvpn/client.crl.next -CAfile /run/secrets/client-ca.pem -noout -verify >/dev/null || die "initial client CRL verification failed"
chmod 0644 /run/openvpn/client.crl.next
mv /run/openvpn/client.crl.next /run/openvpn/client.crl
rm -f /run/openvpn/client.crl.der

sed \
  -e "s|__PORT__|$(sed_escape "${OPENVPN_PORT}")|g" \
  -e "s|__INTERFACE__|$(sed_escape "${OPENVPN_INTERFACE}")|g" \
  -e "s|__NETWORK__|$(sed_escape "${OPENVPN_NETWORK}")|g" \
  -e "s|__NETMASK__|$(sed_escape "${OPENVPN_NETMASK}")|g" \
  -e "s|__DNS__|$(sed_escape "${VPN_DNS}")|g" \
  /usr/share/midorivpn/openvpn/server.conf.template >/run/openvpn/server.conf
chmod 0600 /run/openvpn/server.conf

[ "$(sysctl -n net.ipv4.ip_forward)" = "1" ] || die "pod network namespace must start with net.ipv4.ip_forward=1"
nft delete table ip midori_openvpn 2>/dev/null || true
nft add table ip midori_openvpn
nft 'add chain ip midori_openvpn postrouting { type nat hook postrouting priority srcnat; policy accept; }'
nft add rule ip midori_openvpn postrouting ip saddr "${OPENVPN_NETWORK_CIDR}" masquerade

refresh_crl() {
  while sleep 60; do
    if curl --fail --silent --show-error --proto '=https' --tlsv1.2 "${VPN_CLIENT_CRL_URL}" -o /run/openvpn/client.crl.der && \
      openssl crl -inform DER -in /run/openvpn/client.crl.der -out /run/openvpn/client.crl.next -outform PEM && \
      openssl crl -in /run/openvpn/client.crl.next -CAfile /run/secrets/client-ca.pem -noout -verify >/dev/null; then
      chmod 0644 /run/openvpn/client.crl.next
      mv /run/openvpn/client.crl.next /run/openvpn/client.crl
    else
      rm -f /run/openvpn/client.crl.der /run/openvpn/client.crl.next
      printf 'warning: rejected client CRL refresh\n' >&2
    fi
    rm -f /run/openvpn/client.crl.der
  done
}

export OPENVPN_MANAGEMENT_SOCKET=/run/openvpn/management.sock
export OPENVPN_LOG_PATH=/run/openvpn/openvpn.log
export OPENVPN_HEALTH_LISTEN=127.0.0.1:9194
refresh_crl &
/usr/local/bin/openvpn-health &
exec /usr/sbin/openvpn --config /run/openvpn/server.conf

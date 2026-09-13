#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

output_dir="${1:-}"
passphrase_file=""
if [[ "${2:-}" == --passphrase-file && -n "${3:-}" && $# == 3 ]]; then
  passphrase_file="$3"
elif (($# != 1)); then
  host_die "usage: $0 NEW_OUTPUT_DIRECTORY [--passphrase-file FILE]"
fi
[[ -n "${output_dir}" ]] || host_die "usage: $0 NEW_OUTPUT_DIRECTORY [--passphrase-file FILE]"
[[ "${output_dir}" == /* ]] || host_die "output directory must be absolute"
[[ ! -e "${output_dir}" ]] || host_die "output directory already exists"
host_require_command openssl

ca_passphrase=""
if [[ -n "${passphrase_file}" ]]; then
  host_require_regular_file "${passphrase_file}"
  [[ "$(stat -c '%a' -- "${passphrase_file}")" == 600 ]] || host_die "passphrase file must have mode 0600"
  [[ "$(stat -c '%s' -- "${passphrase_file}")" -le 4096 ]] || host_die "passphrase file is too large"
  mapfile -t passphrase_lines < "${passphrase_file}"
  [[ "${#passphrase_lines[@]}" == 1 ]] || host_die "passphrase file must contain exactly one line"
  ca_passphrase="${passphrase_lines[0]}"
  unset passphrase_lines
else
  [[ -t 0 && -t 1 ]] || host_die "interactive terminal required; do not transmit the CA passphrase through SSH"
  read -r -s -p 'New management CA passphrase: ' ca_passphrase
  printf '\n'
  read -r -s -p 'Confirm management CA passphrase: ' confirmation
  printf '\n'
  [[ "${ca_passphrase}" == "${confirmation}" ]] || host_die "CA passphrases do not match"
  unset confirmation
fi
[[ "${#ca_passphrase}" -ge 20 ]] || host_die "CA passphrase must contain at least 20 characters"

install -d -m 0700 "${output_dir}"
openssl genpkey -algorithm ED25519 -aes-256-cbc -pass fd:3 \
  -out "${output_dir}/ca.key" 3<<<"${ca_passphrase}"
openssl req -x509 -new -key "${output_dir}/ca.key" -passin fd:3 -days 3650 \
  -subj '/CN=MidoriVPN private management CA' -out "${output_dir}/ca.crt" \
  3<<<"${ca_passphrase}"

issue_server() {
  local name="$1" address="$2" extension_file csr
  extension_file="$(mktemp "${output_dir}/.${name}.extensions.XXXXXX")"
  csr="${output_dir}/.${name}.csr"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:%s\n' "${address}" > "${extension_file}"
  openssl genpkey -algorithm ED25519 -out "${output_dir}/${name}.key"
  openssl req -new -key "${output_dir}/${name}.key" -subj "/CN=${address}" -out "${csr}"
  openssl x509 -req -in "${csr}" -CA "${output_dir}/ca.crt" -CAkey "${output_dir}/ca.key" \
    -passin fd:3 -CAcreateserial -days 825 -extfile "${extension_file}" \
    -out "${output_dir}/${name}.crt" 3<<<"${ca_passphrase}"
  rm -f -- "${csr}" "${extension_file}"
  openssl verify -CAfile "${output_dir}/ca.crt" "${output_dir}/${name}.crt" >/dev/null
}

issue_server principal 10.254.240.1
issue_server regional 10.254.240.2
chmod 0600 "${output_dir}"/*.key
chmod 0644 "${output_dir}"/*.crt
openssl pkey -in "${output_dir}/ca.key" -passin fd:3 -noout 3<<<"${ca_passphrase}"
grep -Fq 'BEGIN ENCRYPTED PRIVATE KEY' "${output_dir}/ca.key" || host_die "CA private key is not encrypted"
unset ca_passphrase
host_info "Encrypted private management PKI created in ${output_dir}. Keep ca.key and its passphrase offline and separate; hosts receive only ca.crt and their own certificate/key."

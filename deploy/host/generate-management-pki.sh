#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

output_dir="${1:-}"
[[ -n "${output_dir}" ]] || host_die "usage: $0 NEW_OUTPUT_DIRECTORY"
[[ "${output_dir}" == /* ]] || host_die "output directory must be absolute"
[[ ! -e "${output_dir}" ]] || host_die "output directory already exists"
host_require_command openssl

install -d -m 0700 "${output_dir}"
openssl genpkey -algorithm ED25519 -out "${output_dir}/ca.key"
openssl req -x509 -new -key "${output_dir}/ca.key" -days 3650 \
  -subj '/CN=MidoriVPN private management CA' -out "${output_dir}/ca.crt"

issue_server() {
  local name="$1" address="$2" extension_file csr
  extension_file="$(mktemp "${output_dir}/.${name}.extensions.XXXXXX")"
  csr="${output_dir}/.${name}.csr"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:%s\n' "${address}" > "${extension_file}"
  openssl genpkey -algorithm ED25519 -out "${output_dir}/${name}.key"
  openssl req -new -key "${output_dir}/${name}.key" -subj "/CN=${address}" -out "${csr}"
  openssl x509 -req -in "${csr}" -CA "${output_dir}/ca.crt" -CAkey "${output_dir}/ca.key" \
    -CAcreateserial -days 825 -extfile "${extension_file}" -out "${output_dir}/${name}.crt"
  rm -f -- "${csr}" "${extension_file}"
  openssl verify -CAfile "${output_dir}/ca.crt" "${output_dir}/${name}.crt" >/dev/null
}

issue_server principal 10.254.240.1
issue_server regional 10.254.240.2
chmod 0600 "${output_dir}"/*.key
chmod 0644 "${output_dir}"/*.crt
host_info "Private management PKI created in ${output_dir}. Keep ca.key offline; hosts receive only ca.crt and their own certificate/key."

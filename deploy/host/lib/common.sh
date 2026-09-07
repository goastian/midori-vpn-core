#!/usr/bin/env bash

# Shared primitives for the host deployment scripts. This file deliberately
# parses dotenv files as data; deployment configuration is never sourced.

host_die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

host_info() {
  printf '%s\n' "$*"
}

host_require_command() {
  command -v "$1" >/dev/null 2>&1 || host_die "required command not found: $1"
}

host_require_regular_file() {
  local path="$1"
  [[ -f "${path}" && ! -L "${path}" ]] || host_die "expected a regular non-symlink file: ${path}"
}

host_require_private_directory() {
  local path="$1"
  [[ -d "${path}" && ! -L "${path}" ]] || host_die "expected a real directory: ${path}"
  [[ "$(stat -c '%a' -- "${path}")" == 700 ]] || host_die "directory must have mode 0700: ${path}"
}

host_validate_key() {
  [[ "$1" =~ ^[A-Z][A-Z0-9_]*$ ]] || host_die "invalid environment key: $1"
}

host_load_env() {
  local source_file="$1"
  local destination_name="$2"
  local line key value
  local -n destination="${destination_name}"

  host_require_regular_file "${source_file}"
  destination=()
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ "${line}" != *$'\r'* ]] || host_die "carriage returns are not accepted in ${source_file}"
    [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
    [[ "${line}" == *=* ]] || host_die "invalid dotenv line in ${source_file}"
    key="${line%%=*}"
    value="${line#*=}"
    host_validate_key "${key}"
    [[ ! -v "destination[${key}]" ]] || host_die "duplicate environment key in ${source_file}: ${key}"
    destination["${key}"]="${value}"
  done < "${source_file}"
}

host_require_env() {
  local values_name="$1"
  local key="$2"
  local -n values_ref="${values_name}"
  [[ -v "values_ref[${key}]" && -n "${values_ref[${key}]}" ]] || host_die "missing required environment value: ${key}"
}

host_validate_versioned_image() {
  local value="$1"
  local key="$2"
  [[ "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?/[A-Za-z0-9._/-]+:[0-9]+\.[0-9]+\.[0-9]+([._-][A-Za-z0-9][A-Za-z0-9._-]*)?$ ]] ||
    host_die "${key} must be a fully qualified image with an exact version tag"
}

host_validate_port() {
  local value="$1" key="$2" minimum="${3:-1}"
  if [[ ! "${value}" =~ ^[0-9]+$ ]] || ((value < minimum || value > 65535)); then
    host_die "${key} must be a port from ${minimum} through 65535"
  fi
}

host_validate_absolute_path() {
  local value="$1" key="$2"
  [[ "${value}" =~ ^/[A-Za-z0-9._@/+~-]+$ ]] || host_die "${key} must be an absolute path without whitespace or volume delimiters"
}

host_timestamp() {
  date -u +%Y%m%dT%H%M%SZ
}

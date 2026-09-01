#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly REDOCLY_VERSION="1.34.5"

cd "${PROJECT_DIR}"
exec bash scripts/pod.sh npx --yes "@redocly/cli@${REDOCLY_VERSION}" lint \
    docs/openapi.yaml \
    --skip-rule operation-summary \
    --skip-rule no-path-trailing-slash \
    --max-problems 1

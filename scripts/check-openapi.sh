#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly PROJECT_DIR
readonly REDOCLY_VERSION="2.50.0"

cd "${PROJECT_DIR}"
bash scripts/pod.sh npx --yes "@redocly/cli@${REDOCLY_VERSION}" lint \
    'midorivpn@2.0.0' \
    --max-problems 100
exec bash scripts/pod.sh go test ./internal/api \
    -run '^TestRouterMatchesOpenAPIContract$' \
    -count=1

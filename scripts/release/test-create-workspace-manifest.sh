#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_MANIFEST="${SCRIPT_DIR}/create-workspace-manifest.sh"
SOURCE_LAYOUT="${SCRIPT_DIR}/../lib/workspace-layout.sh"
TEST_DIR="$(mktemp -d /tmp/midorivpn-release-manifest.XXXXXX)"
trap 'rm -rf "${TEST_DIR}"' EXIT

fail() {
  echo "error: $*" >&2
  exit 1
}

initialize_repo() {
  local path="$1"
  git -C "${path}" init -q -b work-branch
  git -C "${path}" add .
  GIT_AUTHOR_DATE='2026-09-02T12:00:00Z' \
  GIT_COMMITTER_DATE='2026-09-02T12:00:00Z' \
    git -C "${path}" -c user.name='MidoriVPN Test' -c user.email='test@invalid' \
      -c commit.gpgsign=false commit -qm 'Create deterministic fixture'
}

create_layout() {
  local base="$1"
  local layout="$2"
  local core="${base}/midori-vpn-core"
  local control desktop extension

  if [[ "${layout}" == "nested" ]]; then
    control="${core}/midori-vpn-control"
    desktop="${core}/midori-vpn-desktop"
    extension="${core}/midorivpn-extension"
  else
    control="${base}/midori-vpn-control"
    desktop="${base}/midori-vpn-desktop"
    extension="${base}/midorivpn-extension"
  fi

  mkdir -p \
    "${core}/scripts/release" "${core}/scripts/lib" \
    "${control}/.container" "${desktop}/agent" "${desktop}/packaging" \
    "${extension}/manifest"
  cp "${SOURCE_MANIFEST}" "${core}/scripts/release/create-workspace-manifest.sh"
  cp "${SOURCE_LAYOUT}" "${core}/scripts/lib/workspace-layout.sh"
  printf '2.0.0\n' >"${core}/VERSION"
  printf 'midori-vpn-control/\nmidori-vpn-desktop/\nmidorivpn-extension/\ntmp/\n' >"${core}/.gitignore"
  printf '{"version":"2.0.0"}\n' >"${control}/package.json"
  : >"${control}/.container/Containerfile"
  printf '{"version":"2.0.0"}\n' >"${desktop}/package.json"
  printf 'module example.invalid/agent\n\ngo 1.27\n' >"${desktop}/agent/go.mod"
  printf 'Version: 2.0.0\n' >"${desktop}/packaging/midori-vpn.spec"
  printf '{"version":"2.0.0"}\n' >"${extension}/package.json"
  printf '{"version":"2.0.0"}\n' >"${extension}/manifest/main.json"

  initialize_repo "${control}"
  initialize_repo "${desktop}"
  initialize_repo "${extension}"
  initialize_repo "${core}"
}

NESTED="${TEST_DIR}/nested"
SIBLING="${TEST_DIR}/sibling"
create_layout "${NESTED}" nested
create_layout "${SIBLING}" sibling

NESTED_MANIFEST="${TEST_DIR}/nested.json"
SIBLING_MANIFEST="${TEST_DIR}/sibling.json"
SOURCE_DATE_EPOCH=1788350400 \
  bash "${NESTED}/midori-vpn-core/scripts/release/create-workspace-manifest.sh" "${NESTED_MANIFEST}" >/dev/null
SOURCE_DATE_EPOCH=1788350400 \
  bash "${SIBLING}/midori-vpn-core/scripts/release/create-workspace-manifest.sh" "${SIBLING_MANIFEST}" >/dev/null

cmp -s "${NESTED_MANIFEST}" "${SIBLING_MANIFEST}" || fail "nested and sibling manifests differ"
jq -e '
  .schema_version == 2 and
  .product_version == "2.0.0" and
  .source_date_epoch == 1788350400 and
  ([.repositories[].component] == ["core", "control", "desktop", "extension"]) and
  ([.repositories[].path] == [".", "midori-vpn-control", "midori-vpn-desktop", "midorivpn-extension"])
' "${NESTED_MANIFEST}" >/dev/null || fail "manifest contract is invalid"

git -C "${SIBLING}/midori-vpn-control" switch -q -c other-branch
if SOURCE_DATE_EPOCH=1788350400 \
  bash "${SIBLING}/midori-vpn-core/scripts/release/create-workspace-manifest.sh" "${TEST_DIR}/mismatch.json" \
    >"${TEST_DIR}/mismatch.out" 2>"${TEST_DIR}/mismatch.err"; then
  fail "manifest accepted mismatched repository branches"
fi
rg -F 'control ref state other-branch must match Core work-branch' "${TEST_DIR}/mismatch.err" >/dev/null || \
  fail "branch mismatch error is not actionable"
git -C "${SIBLING}/midori-vpn-control" switch -q work-branch

for repository in midori-vpn-core midori-vpn-control midori-vpn-desktop midorivpn-extension; do
  git -C "${SIBLING}/${repository}" switch -q --detach
done
SOURCE_DATE_EPOCH=1788350400 \
  bash "${SIBLING}/midori-vpn-core/scripts/release/create-workspace-manifest.sh" "${TEST_DIR}/detached.json" >/dev/null
jq -e '[.repositories[].branch] == ["detached", "detached", "detached", "detached"]' \
  "${TEST_DIR}/detached.json" >/dev/null || fail "detached release refs were not recorded canonically"

mv "${SIBLING}/midorivpn-extension" "${SIBLING}/missing-extension"
if SOURCE_DATE_EPOCH=1788350400 \
  bash "${SIBLING}/midori-vpn-core/scripts/release/create-workspace-manifest.sh" "${TEST_DIR}/missing.json" \
    >"${TEST_DIR}/missing.out" 2>"${TEST_DIR}/missing.err"; then
  fail "manifest accepted a missing extension repository"
fi
rg -F 'Extension repository was not found nested under Core or beside it' "${TEST_DIR}/missing.err" >/dev/null || \
  fail "missing repository error is not actionable"

echo "Workspace release manifest layout tests passed."

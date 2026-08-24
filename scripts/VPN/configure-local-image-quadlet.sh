#!/usr/bin/env bash
set -Eeuo pipefail

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

QUADLET_FILE="${1:-}"

[[ -n "$QUADLET_FILE" ]] || die "usage: $0 <container.quadlet>"
[[ -f "$QUADLET_FILE" ]] || die "Quadlet not found: $QUADLET_FILE"
grep -Eq '^Image=localhost/' "$QUADLET_FILE" || die "Quadlet does not use a local image"

backup_file="${QUADLET_FILE}.pre-local-pull-$(date -u +%Y%m%dT%H%M%SZ)"
cp -a -- "$QUADLET_FILE" "$backup_file"

temporary_file="$(mktemp "${QUADLET_FILE}.XXXXXX")"
trap 'rm -f -- "$temporary_file"' EXIT

awk '
  /^Pull=/ { if (!pull_written) { print "Pull=never"; pull_written=1 }; next }
  /^AutoUpdate=/ { next }
  { print }
  END { if (!pull_written) print "Pull=never" }
' "$QUADLET_FILE" > "$temporary_file"

chmod --reference="$QUADLET_FILE" "$temporary_file"
mv -- "$temporary_file" "$QUADLET_FILE"
trap - EXIT

grep -qx 'Pull=never' "$QUADLET_FILE" || die "failed to set Pull=never"
printf 'Updated %s; backup: %s\n' "$QUADLET_FILE" "$backup_file"

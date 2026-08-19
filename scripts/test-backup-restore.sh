#!/usr/bin/env bash
# ==============================================================================
# Midori VPN — Automated PostgreSQL Backup & Restore Validation Script (SEC-01)
# ==============================================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/tmp/midori-backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="$BACKUP_DIR/midori_vpn_backup_$TIMESTAMP.sql.gz"
RESTORE_DB="midori_vpn_restore_test_$TIMESTAMP"

mkdir -p "$BACKUP_DIR"

echo "=== [1/4] Starting PostgreSQL Backup ==="
podman exec -t postgres-db pg_dump -U midori -d midori_vpn | gzip > "$BACKUP_FILE"
echo "Backup saved to: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"

echo "=== [2/4] Creating Ephemeral Test Database ==="
podman exec -t postgres-db psql -U midori -d postgres -c "CREATE DATABASE $RESTORE_DB;"

echo "=== [3/4] Restoring into Ephemeral Database ==="
gunzip -c "$BACKUP_FILE" | podman exec -i postgres-db psql -U midori -d "$RESTORE_DB"

echo "=== [4/4] Validating Data Integrity ==="
USER_COUNT=$(podman exec -t postgres-db psql -U midori -d "$RESTORE_DB" -t -c "SELECT COUNT(*) FROM users;")
PEER_COUNT=$(podman exec -t postgres-db psql -U midori -d "$RESTORE_DB" -t -c "SELECT COUNT(*) FROM peers;")

echo "Restored User Count: $(echo "$USER_COUNT" | tr -d ' ')"
echo "Restored Peer Count: $(echo "$PEER_COUNT" | tr -d ' ')"

echo "=== Cleanup Ephemeral Database ==="
podman exec -t postgres-db psql -U midori -d postgres -c "DROP DATABASE $RESTORE_DB;"

echo "=== Backup & Restore Validation PASSED ==="

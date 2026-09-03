#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-docker.io/library/postgres:18-alpine}"
container="midori-migration-test-${BASHPID}-${RANDOM}-${RANDOM}"

cleanup() {
  podman rm -f "${container}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

podman run -d --name "${container}" \
  -e POSTGRES_USER=midori \
  -e POSTGRES_PASSWORD=migration-test-only \
  -e POSTGRES_DB=midori_vpn \
  --tmpfs /var/lib/postgresql:rw,size=512m \
  -v "${ROOT_DIR}/internal/db/migrations:/migrations:ro,Z" \
  -v "${ROOT_DIR}/internal/db/schema.sql:/schema.sql:ro,Z" \
  "${POSTGRES_IMAGE}" >/dev/null

for _ in {1..60}; do
  if podman exec "${container}" pg_isready -U midori -d midori_vpn >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
podman exec "${container}" pg_isready -U midori -d midori_vpn >/dev/null

podman exec "${container}" sh -ceu '
  for file in /migrations/*.up.sql; do
    [ "$(basename "$file")" = "000012_persistent_devices.up.sql" ] && break
    psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -f "$file" >/dev/null
  done
'

# Seed the version-11 schema so migration 12 proves its historical backfill.
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c "
  INSERT INTO users (id, authentik_uid, email)
  VALUES ('10000000-0000-4000-8000-000000000001', 'migration-device-user', 'migration@test.invalid');
  INSERT INTO vpn_servers (id, name, host)
  VALUES ('20000000-0000-4000-8000-000000000001', 'Migration Server', 'migration.test.invalid');
  INSERT INTO vpn_server_transports (server_id, protocol, endpoint, port, enabled, priority)
  VALUES ('20000000-0000-4000-8000-000000000001', 'wireguard', 'migration.test.invalid', 51820, FALSE, 100);
  INSERT INTO peers (id, user_id, server_id, public_key, assigned_ip, is_active, device_name, created_at)
  VALUES
    ('30000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'active-key-one', '10.88.0.2/32', TRUE, 'desktop', NOW() - INTERVAL '3 hours'),
    ('30000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'active-key-two', '10.88.0.3/32', TRUE, 'desktop', NOW() - INTERVAL '2 hours'),
    ('30000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'inactive-key', '10.88.0.4/32', FALSE, 'old-desktop', NOW() - INTERVAL '1 hour');
  INSERT INTO device_certificates (
    id, user_id, server_id, device_name, serial_number, certificate_pem,
    public_key_sha256, not_before, not_after, revoked_at
  ) VALUES
    ('40000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'desktop', '1001', 'CERT-ONE', repeat('a', 64), NOW() - INTERVAL '1 day', NOW() + INTERVAL '1 day', NULL),
    ('40000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'certificate-only', '1002', 'CERT-TWO', repeat('b', 64), NOW() - INTERVAL '1 day', NOW() + INTERVAL '1 day', NULL),
    ('40000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'revoked-device', '1003', 'CERT-THREE', repeat('c', 64), NOW() - INTERVAL '2 days', NOW() + INTERVAL '1 day', NOW() - INTERVAL '1 day');
" >/dev/null

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000012_persistent_devices.up.sql >/dev/null
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000013_peer_operations.up.sql >/dev/null
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000014_previous_peer_operation.up.sql >/dev/null

remaining="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT count(*) FROM information_schema.columns WHERE table_name = 'vpn_servers' AND column_name IN ('proxy_port','proxy_scheme','wss_tunnel_enabled','wss_host','wss_port')")"
[ "${remaining}" = "0" ] || { printf 'error: migration 9 left %s retired columns\n' "${remaining}" >&2; exit 1; }

certificate_table="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT to_regclass('public.device_certificates') IS NOT NULL")"
[ "${certificate_table}" = "t" ] || { printf 'error: migration 10 did not create device_certificates\n' >&2; exit 1; }

mesh_capabilities="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND ((table_name = 'mesh_members' AND column_name IN ('proxy_scheme','supports_tcp','supports_udp')) OR (table_name = 'user_exit_node' AND column_name IN ('proxy_scheme','supports_tcp','supports_udp')))")"
[ "${mesh_capabilities}" = "6" ] || { printf 'error: migration 11 created %s of 6 exit-node capability columns\n' "${mesh_capabilities}" >&2; exit 1; }

device_table="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT to_regclass('public.devices') IS NOT NULL")"
[ "${device_table}" = "t" ] || { printf 'error: migration 12 did not create devices\n' >&2; exit 1; }

legacy_devices="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT COUNT(*) FROM devices WHERE user_id = '10000000-0000-4000-8000-000000000001' AND client_instance_id IS NULL AND device_type = 'manual'")"
[ "${legacy_devices}" = "4" ] || { printf 'error: migration 12 created %s legacy devices, expected 4\n' "${legacy_devices}" >&2; exit 1; }

active_peer_devices="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT COUNT(DISTINCT device_id) FROM peers WHERE is_active = TRUE AND device_id IS NOT NULL")"
[ "${active_peer_devices}" = "2" ] || { printf 'error: active peers mapped to %s distinct devices, expected 2\n' "${active_peer_devices}" >&2; exit 1; }

inactive_peer_devices="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT COUNT(*) FROM peers WHERE is_active = FALSE AND device_id IS NOT NULL")"
[ "${inactive_peer_devices}" = "0" ] || { printf 'error: inactive peers unexpectedly created visible devices\n' >&2; exit 1; }

certificate_devices="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT COUNT(*) FILTER (WHERE revoked_at IS NULL AND device_id IS NOT NULL) || ':' || COUNT(*) FILTER (WHERE revoked_at IS NOT NULL AND device_id IS NULL) FROM device_certificates")"
[ "${certificate_devices}" = "2:1" ] || { printf 'error: certificate backfill mismatch: %s\n' "${certificate_devices}" >&2; exit 1; }

if podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c \
  "UPDATE peers SET device_id = NULL WHERE id = '30000000-0000-4000-8000-000000000001'" >/dev/null 2>&1; then
  printf 'error: migration 12 allowed an active peer without device_id\n' >&2
  exit 1
fi

operation_table="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT to_regclass('public.peer_operations') IS NOT NULL")"
[ "${operation_table}" = "t" ] || { printf 'error: migration 13 did not create peer_operations\n' >&2; exit 1; }

# Live operations are exclusive by device and key and block deletion of every
# parent required to reconcile them.
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c "
  INSERT INTO users (id, authentik_uid, email)
  VALUES ('10000000-0000-4000-8000-000000000013', 'operation-user', 'operation@test.invalid');
  INSERT INTO vpn_servers (id, name, host)
  VALUES ('20000000-0000-4000-8000-000000000013', 'Operation Server', 'operation.test.invalid');
  INSERT INTO vpn_server_transports (server_id, protocol, endpoint, port, enabled, priority)
  VALUES ('20000000-0000-4000-8000-000000000013', 'wireguard', 'operation.test.invalid', 51820, FALSE, 100);
  INSERT INTO devices (id, user_id, client_instance_id, reported_name, device_type)
  VALUES ('50000000-0000-4000-8000-000000000013', '10000000-0000-4000-8000-000000000013',
          '60000000-0000-4000-8000-000000000013', 'operation-host', 'desktop');
  INSERT INTO peer_operations (
    id, action, state, user_id, device_id, server_id, public_key,
    capacity_reserved, attempts
  ) VALUES (
    '70000000-0000-4000-8000-000000000013', 'connect', 'pending',
    '10000000-0000-4000-8000-000000000013', '50000000-0000-4000-8000-000000000013',
    '20000000-0000-4000-8000-000000000013', repeat('A', 43) || '=', TRUE, 1
  );
" >/dev/null
for parent_delete in \
  "DELETE FROM users WHERE id = '10000000-0000-4000-8000-000000000013'" \
  "DELETE FROM devices WHERE id = '50000000-0000-4000-8000-000000000013'" \
  "DELETE FROM vpn_servers WHERE id = '20000000-0000-4000-8000-000000000013'"; do
  if podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c "${parent_delete}" >/dev/null 2>&1; then
    printf 'error: migration 13 allowed parent deletion with a live operation\n' >&2
    exit 1
  fi
done
if podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c "
  INSERT INTO peer_operations (
    id, action, state, user_id, device_id, server_id, public_key
  ) VALUES (
    '70000000-0000-4000-8000-000000000014', 'connect', 'pending',
    '10000000-0000-4000-8000-000000000013', '50000000-0000-4000-8000-000000000013',
    '20000000-0000-4000-8000-000000000013', repeat('B', 43) || '='
  )" >/dev/null 2>&1; then
  printf 'error: migration 13 allowed concurrent live operations for one device\n' >&2
  exit 1
fi
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c "
  UPDATE peer_operations
  SET state = 'failed', capacity_reserved = FALSE, last_error = 'test terminal state'
  WHERE id = '70000000-0000-4000-8000-000000000013';
  DELETE FROM users WHERE id = '10000000-0000-4000-8000-000000000013';
" >/dev/null

# Secondary adapter references are intentionally non-unique.
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c \
  "UPDATE devices SET adapter_reference = 'net-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE id IN (SELECT id FROM devices ORDER BY id LIMIT 2)" >/dev/null

# A registered installation ID is unique only within one user.
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c \
  "INSERT INTO devices (user_id, client_instance_id, reported_name, device_type) VALUES ('10000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000001', 'registered-one', 'desktop')" >/dev/null
if podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c \
  "INSERT INTO devices (user_id, client_instance_id, reported_name, device_type) VALUES ('10000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000001', 'registered-two', 'desktop')" >/dev/null 2>&1; then
  printf 'error: migration 12 allowed a duplicate client_instance_id for one user\n' >&2
  exit 1
fi

if podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c \
  "UPDATE device_certificates SET device_id = NULL WHERE id = '40000000-0000-4000-8000-000000000001'" >/dev/null 2>&1; then
  printf 'error: migration 12 allowed an unrevoked certificate without device_id\n' >&2
  exit 1
fi

# Composite ownership prevents cross-user device references while deferred
# checks still allow deleting a user and all of its related rows atomically.
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c "
  INSERT INTO users (id, authentik_uid, email)
  VALUES ('10000000-0000-4000-8000-000000000002', 'cascade-device-user', 'cascade@test.invalid');
" >/dev/null
if podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c \
  "INSERT INTO peers (user_id, server_id, public_key, assigned_ip, is_active, device_name, device_id) VALUES ('10000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000001', 'wrong-owner-key', '10.88.0.20/32', FALSE, 'wrong-owner', (SELECT id FROM devices WHERE user_id = '10000000-0000-4000-8000-000000000001' LIMIT 1))" >/dev/null 2>&1; then
  printf 'error: migration 12 allowed a cross-user device reference\n' >&2
  exit 1
fi
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c "
  INSERT INTO devices (id, user_id, client_instance_id, reported_name, device_type)
  VALUES ('50000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000002', '60000000-0000-4000-8000-000000000002', 'cascade-host', 'desktop');
  INSERT INTO peers (user_id, server_id, public_key, assigned_ip, is_active, device_name, device_id)
  VALUES ('10000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000001', 'cascade-key', '10.88.0.21/32', TRUE, 'cascade-host', '50000000-0000-4000-8000-000000000002');
  INSERT INTO device_certificates (
    id, user_id, server_id, device_name, device_id, serial_number,
    certificate_pem, public_key_sha256, not_before, not_after
  ) VALUES (
    '40000000-0000-4000-8000-000000000020', '10000000-0000-4000-8000-000000000002',
    '20000000-0000-4000-8000-000000000001', 'cascade-host', '50000000-0000-4000-8000-000000000002',
    '1020', 'CERT-CASCADE', repeat('f', 64), NOW() - INTERVAL '1 day', NOW() + INTERVAL '1 day'
  );
  DELETE FROM users WHERE id = '10000000-0000-4000-8000-000000000002';
" >/dev/null
cascade_rows="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT (SELECT COUNT(*) FROM devices WHERE user_id = '10000000-0000-4000-8000-000000000002') + (SELECT COUNT(*) FROM peers WHERE user_id = '10000000-0000-4000-8000-000000000002') + (SELECT COUNT(*) FROM device_certificates WHERE user_id = '10000000-0000-4000-8000-000000000002')")"
[ "${cascade_rows}" = "0" ] || { printf 'error: user cascade left %s device-related rows\n' "${cascade_rows}" >&2; exit 1; }

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000014_previous_peer_operation.down.sql >/dev/null
previous_operation_column="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'peer_operations' AND column_name = 'previous_operation_id'")"
[ "${previous_operation_column}" = "0" ] || { printf 'error: migration 14 rollback left previous_operation_id\n' >&2; exit 1; }

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000013_peer_operations.down.sql >/dev/null
operation_artifacts="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT (to_regclass('public.peer_operations') IS NOT NULL)::int + COUNT(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'peers' AND column_name = 'provision_operation_id'")"
[ "${operation_artifacts}" = "0" ] || { printf 'error: migration 13 rollback left %s operation artifacts\n' "${operation_artifacts}" >&2; exit 1; }

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000012_persistent_devices.down.sql >/dev/null
device_columns="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'public' AND ((table_name = 'peers' AND column_name = 'device_id') OR (table_name = 'device_certificates' AND column_name = 'device_id'))")"
[ "${device_columns}" = "0" ] || { printf 'error: migration 12 rollback left %s device_id columns\n' "${device_columns}" >&2; exit 1; }
device_table="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT to_regclass('public.devices') IS NOT NULL")"
[ "${device_table}" = "f" ] || { printf 'error: migration 12 rollback left devices\n' >&2; exit 1; }

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000011_mesh_exit_node_capabilities.down.sql >/dev/null
mesh_capabilities="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND ((table_name = 'mesh_members' AND column_name IN ('proxy_scheme','supports_tcp','supports_udp')) OR (table_name = 'user_exit_node' AND column_name IN ('proxy_scheme','supports_tcp','supports_udp')))")"
[ "${mesh_capabilities}" = "0" ] || { printf 'error: migration 11 rollback left %s exit-node capability columns\n' "${mesh_capabilities}" >&2; exit 1; }
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000011_mesh_exit_node_capabilities.up.sql >/dev/null

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000010_device_certificates.down.sql >/dev/null
certificate_table="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT to_regclass('public.device_certificates') IS NOT NULL")"
[ "${certificate_table}" = "f" ] || { printf 'error: migration 10 rollback left device_certificates\n' >&2; exit 1; }
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000010_device_certificates.up.sql >/dev/null

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000009_remove_legacy_transport_columns.down.sql >/dev/null
restored="$(podman exec "${container}" psql -U midori -d midori_vpn -Atc \
  "SELECT count(*) FROM information_schema.columns WHERE table_name = 'vpn_servers' AND column_name IN ('proxy_port','proxy_scheme','wss_tunnel_enabled','wss_host','wss_port')")"
[ "${restored}" = "5" ] || { printf 'error: migration 9 rollback restored %s of 5 columns\n' "${restored}" >&2; exit 1; }

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000009_remove_legacy_transport_columns.up.sql >/dev/null

podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000012_persistent_devices.up.sql >/dev/null
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000013_peer_operations.up.sql >/dev/null
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn \
  -f /migrations/000014_previous_peer_operation.up.sql >/dev/null

# The device-based certificate key permits equal hostnames on distinct
# registered installations without merging either device.
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_vpn -c "
  INSERT INTO devices (id, user_id, client_instance_id, reported_name, device_type)
  VALUES
    ('50000000-0000-4000-8000-000000000011', '10000000-0000-4000-8000-000000000001', '60000000-0000-4000-8000-000000000011', 'same-host', 'desktop'),
    ('50000000-0000-4000-8000-000000000012', '10000000-0000-4000-8000-000000000001', '60000000-0000-4000-8000-000000000012', 'same-host', 'desktop');
  INSERT INTO device_certificates (
    id, user_id, server_id, device_id, device_name, serial_number,
    certificate_pem, public_key_sha256, not_before, not_after
  ) VALUES
    ('40000000-0000-4000-8000-000000000011', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000011', 'same-host', '1011', 'CERT-ELEVEN', repeat('d', 64), NOW() - INTERVAL '1 day', NOW() + INTERVAL '1 day'),
    ('40000000-0000-4000-8000-000000000012', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', '50000000-0000-4000-8000-000000000012', 'same-host', '1012', 'CERT-TWELVE', repeat('e', 64), NOW() - INTERVAL '1 day', NOW() + INTERVAL '1 day');
" >/dev/null

# The consolidated schema must independently create a current database.
podman exec "${container}" createdb -U midori midori_schema_test
podman exec "${container}" psql -v ON_ERROR_STOP=1 -U midori -d midori_schema_test \
  -f /schema.sql >/dev/null
schema_devices="$(podman exec "${container}" psql -U midori -d midori_schema_test -Atc \
  "SELECT to_regclass('public.devices') IS NOT NULL")"
[ "${schema_devices}" = "t" ] || { printf 'error: consolidated schema did not create devices\n' >&2; exit 1; }
schema_operations="$(podman exec "${container}" psql -U midori -d midori_schema_test -Atc \
  "SELECT to_regclass('public.peer_operations') IS NOT NULL")"
[ "${schema_operations}" = "t" ] || { printf 'error: consolidated schema did not create peer_operations\n' >&2; exit 1; }

printf 'Migration chain 1-14, migrations 9-14 rollback, and consolidated schema verified on PostgreSQL 18.\n'

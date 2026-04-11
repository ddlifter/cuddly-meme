#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$ROOT_DIR/tests"

PGDATA="${PGDATA:-$HOME/pg_data}"
DBNAME="${DBNAME:-postgres}"
PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"
MASTER_HEX="${MASTER_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

ARCHIVE_DIR="${OPENTDE_WAL_ARCHIVE_DIR:-$PGDATA/pg_wal_archive_tde}"
KEY_HEX="${OPENTDE_WAL_ARCHIVE_KEY_HEX:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"

export OPENTDE_WAL_ARCHIVE_DIR="$ARCHIVE_DIR"
export OPENTDE_WAL_ARCHIVE_KEY_HEX="$KEY_HEX"

export VAULT_ADDR="${VAULT_ADDR:-${OPENTDE_VAULT_ADDR:-http://127.0.0.1:8200}}"
export VAULT_PATH="${VAULT_PATH:-${OPENTDE_VAULT_PATH:-secret/pg_tde}}"
export VAULT_FIELD="${VAULT_FIELD:-${OPENTDE_VAULT_FIELD:-master_key}}"
export VAULT_TOKEN="${VAULT_TOKEN:-${OPENTDE_VAULT_TOKEN:-root}}"
export OPENTDE_VAULT_ADDR="${OPENTDE_VAULT_ADDR:-$VAULT_ADDR}"
export OPENTDE_VAULT_PATH="${OPENTDE_VAULT_PATH:-$VAULT_PATH}"
export OPENTDE_VAULT_FIELD="${OPENTDE_VAULT_FIELD:-$VAULT_FIELD}"
export OPENTDE_VAULT_TOKEN="${OPENTDE_VAULT_TOKEN:-$VAULT_TOKEN}"

PSQL="$PGBIN/psql"
PG_CTL="$PGBIN/pg_ctl"

fail() {
  echo "[WAL-E2E][ERROR] $*" >&2
  exit 1
}

wait_for_ready() {
  local i
  for i in {1..45}; do
    if "$PSQL" -d "$DBNAME" -Atc "SELECT 1" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

sql() {
  "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 "$@"
}

sql_val() {
  "$PSQL" -d "$DBNAME" -At -v ON_ERROR_STOP=1 -c "$1"
}

ensure_exec() {
  chmod +x "$TEST_DIR/wal_archive_encrypt.sh" "$TEST_DIR/wal_restore_decrypt.sh"
}

restart_with_archive_mode() {
  local archive_cmd
  archive_cmd="$TEST_DIR/wal_archive_encrypt.sh \"%p\" \"%f\""

  "$PG_CTL" -D "$PGDATA" stop -m fast -w >/dev/null 2>&1 || true
  "$PG_CTL" -D "$PGDATA" start -w \
    -o "-c shared_preload_libraries=opentde -c io_method=sync -c archive_mode=on -c wal_level=replica -c archive_timeout=10s -c archive_command='$archive_cmd'" \
    >/dev/null

  wait_for_ready || fail "PostgreSQL did not become ready"
}

wait_for_archived() {
  local wal_name="$1"
  local i

  for i in {1..30}; do
    if [[ -f "$ARCHIVE_DIR/$wal_name.tde" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

echo "[WAL-E2E] PGDATA=$PGDATA"
echo "[WAL-E2E] ARCHIVE_DIR=$ARCHIVE_DIR"

ensure_exec
rm -rf "$ARCHIVE_DIR"
mkdir -p "$ARCHIVE_DIR"

restart_with_archive_mode

MARK="WAL_ARCHIVE_E2E_MARK_$(date +%s)"

echo "[WAL-E2E] Preparing schema and generating WAL..."
sql -c "DROP TABLE IF EXISTS wal_archive_probe;"
sql -c "DROP EXTENSION IF EXISTS opentde CASCADE;"
sql -c "CREATE EXTENSION opentde;"
sql -c "SELECT opentde_set_master_key(decode('$MASTER_HEX','hex'));"
sql -c "CREATE TABLE wal_archive_probe(id int, v text);"
sql -c "SELECT opentde_enable_table_encryption('wal_archive_probe'::regclass);"
sql -c "INSERT INTO wal_archive_probe VALUES (1, '$MARK');"
sql -c "CHECKPOINT;"
SWITCHED_WAL="$(sql_val "SELECT pg_walfile_name(pg_switch_wal())")"

[[ -n "$SWITCHED_WAL" ]] || fail "Failed to determine switched WAL file name"
echo "[WAL-E2E] WAL segment: $SWITCHED_WAL"

wait_for_archived "$SWITCHED_WAL" || fail "Archived encrypted WAL segment not found: $ARCHIVE_DIR/$SWITCHED_WAL.tde"

if grep -a -q "$MARK" "$ARCHIVE_DIR/$SWITCHED_WAL.tde"; then
  fail "Plaintext marker found in encrypted WAL archive"
fi

echo "[WAL-E2E] Archive plaintext check passed"

RESTORED="$ARCHIVE_DIR/$SWITCHED_WAL.restored"
"$TEST_DIR/wal_restore_decrypt.sh" "$SWITCHED_WAL" "$RESTORED"

[[ -f "$RESTORED" ]] || fail "Restore output file was not created"

if ! grep -a -q "$MARK" "$RESTORED"; then
  fail "Marker not found in restored WAL segment"
fi

if [[ -f "$PGDATA/pg_wal/$SWITCHED_WAL" ]]; then
  ORIG_SHA="$(sha256sum "$PGDATA/pg_wal/$SWITCHED_WAL" | awk '{print $1}')"
  REST_SHA="$(sha256sum "$RESTORED" | awk '{print $1}')"
  [[ "$ORIG_SHA" == "$REST_SHA" ]] || fail "SHA mismatch between original and restored WAL"
  echo "[WAL-E2E] SHA roundtrip check passed"
else
  echo "[WAL-E2E][WARN] Original WAL segment not present in pg_wal; SHA check skipped"
fi

echo "[WAL-E2E] OK: archive_command encryption + restore decryption verified"

#!/usr/bin/env bash
set -euo pipefail

PGDATA="${PGDATA:-$HOME/pg_data}"
DBNAME="${DBNAME:-postgres}"
PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"
MASTER_HEX="${MASTER_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

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

PLAIN_MARK="WAL_PLAIN_MARK_$(date +%s)"
ENC_MARK="WAL_ENC_MARK_$(date +%s)"

echo "[WAL-PROBE] Restarting server with OpenTDE preload..."
"$PG_CTL" -D "$PGDATA" restart -o "-c shared_preload_libraries=opentde -c io_method=sync" >/dev/null

echo "[WAL-PROBE] Inserting probe rows..."
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "DROP TABLE IF EXISTS wal_probe_plain;"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "DROP TABLE IF EXISTS wal_probe_enc;"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "DROP EXTENSION IF EXISTS opentde CASCADE;"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "CREATE EXTENSION opentde;"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "SELECT opentde_set_master_key(decode('$MASTER_HEX','hex'));"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "CREATE TABLE wal_probe_plain(id int, v text);"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "CREATE TABLE wal_probe_enc(id int, v text);"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "SELECT opentde_enable_table_encryption('wal_probe_enc'::regclass);"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "INSERT INTO wal_probe_plain VALUES (1, '$PLAIN_MARK');"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "INSERT INTO wal_probe_enc VALUES (1, '$ENC_MARK');"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "CHECKPOINT;"
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "SELECT pg_switch_wal();" >/dev/null

echo "[WAL-PROBE] Probing pg_wal for markers..."
echo "PLAIN_MARK=$PLAIN_MARK"
echo "ENC_MARK=$ENC_MARK"

echo "-- plain marker matches --"
if ! grep -aob "$PLAIN_MARK" "$PGDATA"/pg_wal/0*; then
  echo "NO_PLAIN_MATCH"
fi

echo "-- encrypted-table marker matches --"
if ! grep -aob "$ENC_MARK" "$PGDATA"/pg_wal/0*; then
  echo "NO_ENC_MATCH"
fi

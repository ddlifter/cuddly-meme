#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS_DIR="$ROOT_DIR/tests"

PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"
DBNAME="${DBNAME:-postgres}"
DBUSER="${DBUSER:-postgres}"
PRIMARY_PORT="${PRIMARY_PORT:-55432}"
PITR_PORT="${PITR_PORT:-55433}"
STANDBY_PORT="${STANDBY_PORT:-55434}"
HTTP_PORT="${HTTP_PORT:-18080}"
MASTER_HEX="${MASTER_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

OPENTDE_WAL_ARCHIVE_KEY_HEX="${OPENTDE_WAL_ARCHIVE_KEY_HEX:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"

export VAULT_ADDR="${VAULT_ADDR:-${OPENTDE_VAULT_ADDR:-http://127.0.0.1:8200}}"
export VAULT_PATH="${VAULT_PATH:-${OPENTDE_VAULT_PATH:-secret/pg_tde}}"
export VAULT_FIELD="${VAULT_FIELD:-${OPENTDE_VAULT_FIELD:-master_key}}"
export VAULT_TOKEN="${VAULT_TOKEN:-${OPENTDE_VAULT_TOKEN:-root}}"
export OPENTDE_VAULT_ADDR="${OPENTDE_VAULT_ADDR:-$VAULT_ADDR}"
export OPENTDE_VAULT_PATH="${OPENTDE_VAULT_PATH:-$VAULT_PATH}"
export OPENTDE_VAULT_FIELD="${OPENTDE_VAULT_FIELD:-$VAULT_FIELD}"
export OPENTDE_VAULT_TOKEN="${OPENTDE_VAULT_TOKEN:-$VAULT_TOKEN}"
export OPENTDE_WAL_ARCHIVE_KEY_HEX

INITDB="$PGBIN/initdb"
PSQL="$PGBIN/psql"
PG_CTL="$PGBIN/pg_ctl"
PG_BASEBACKUP="$PGBIN/pg_basebackup"

WORK_DIR="${WORK_DIR:-/tmp/opentde_wal_pitr_replica_$$}"
KEEP_WORKDIR="${KEEP_WORKDIR:-0}"
PRIMARY_DATA="$WORK_DIR/primary"
PRIMARY_ARCHIVE_DIR="$WORK_DIR/archive_primary"
PRIMARY_RESTORE_TMP="$WORK_DIR/restore_tmp_primary"
PITR_BASE="$WORK_DIR/pitr_base"
PITR_DATA="$WORK_DIR/pitr"
PITR_RESTORE_TMP="$WORK_DIR/restore_tmp_pitr"
STANDBY_DATA="$WORK_DIR/standby"
STANDBY_RESTORE_TMP="$WORK_DIR/restore_tmp_standby"
NET_SAMPLE_TDE="$WORK_DIR/net_sample.tde"
NET_SAMPLE_DEC="$WORK_DIR/net_sample.dec"
HTTP_LOG="$WORK_DIR/http.log"

HTTP_PID=""
PRIMARY_RUNNING=0
PITR_RUNNING=0
STANDBY_RUNNING=0

fail() {
  echo "[WAL-PITR-REPL][ERROR] $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"
}

wait_for_ready() {
  local port="$1"
  local i

  for i in {1..60}; do
    if "$PSQL" -h 127.0.0.1 -p "$port" -U "$DBUSER" -d "$DBNAME" -Atc "SELECT 1" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  return 1
}

psqlp() {
  local port="$1"
  shift
  "$PSQL" -h 127.0.0.1 -p "$port" -U "$DBUSER" -d "$DBNAME" -v ON_ERROR_STOP=1 "$@"
}

psqlp_val() {
  local port="$1"
  local q="$2"
  "$PSQL" -h 127.0.0.1 -p "$port" -U "$DBUSER" -d "$DBNAME" -At -v ON_ERROR_STOP=1 -c "$q"
}

cleanup() {
  set +e

  if [[ -n "$HTTP_PID" ]]; then
    kill "$HTTP_PID" >/dev/null 2>&1 || true
  fi

  if [[ $STANDBY_RUNNING -eq 1 ]]; then
    "$PG_CTL" -D "$STANDBY_DATA" stop -m fast -w >/dev/null 2>&1 || true
  fi

  if [[ $PITR_RUNNING -eq 1 ]]; then
    "$PG_CTL" -D "$PITR_DATA" stop -m fast -w >/dev/null 2>&1 || true
  fi

  if [[ $PRIMARY_RUNNING -eq 1 ]]; then
    "$PG_CTL" -D "$PRIMARY_DATA" stop -m fast -w >/dev/null 2>&1 || true
  fi

  if [[ "$KEEP_WORKDIR" != "1" ]]; then
    rm -rf "$WORK_DIR"
  fi
}

trap cleanup EXIT

start_http_archive_server() {
  pushd "$PRIMARY_ARCHIVE_DIR" >/dev/null
  python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 >"$HTTP_LOG" 2>&1 &
  HTTP_PID=$!
  popd >/dev/null

  sleep 1
  kill -0 "$HTTP_PID" >/dev/null 2>&1 || fail "Failed to start HTTP archive server"
}

start_primary() {
  local archive_cmd
  local primary_log

  rm -rf "$PRIMARY_DATA" "$PRIMARY_ARCHIVE_DIR" "$PRIMARY_RESTORE_TMP"
  mkdir -p "$PRIMARY_ARCHIVE_DIR" "$PRIMARY_RESTORE_TMP"
  primary_log="$WORK_DIR/primary.log"

  "$INITDB" -D "$PRIMARY_DATA" -U postgres >/dev/null

  cat >> "$PRIMARY_DATA/pg_hba.conf" <<'HBA'
host all all 127.0.0.1/32 trust
host replication all 127.0.0.1/32 trust
HBA

  archive_cmd="$TESTS_DIR/wal_archive_encrypt.sh \"%p\" \"%f\""

  OPENTDE_WAL_ARCHIVE_DIR="$PRIMARY_ARCHIVE_DIR" "$PG_CTL" -D "$PRIMARY_DATA" start -w -l "$primary_log" \
    -o "-p $PRIMARY_PORT -c listen_addresses=127.0.0.1 -c shared_preload_libraries=opentde -c io_method=sync -c wal_level=replica -c max_wal_senders=10 -c hot_standby=on -c archive_mode=on -c archive_timeout=5s -c archive_command='${archive_cmd}'" \
    >/dev/null || {
      tail -n 80 "$primary_log" >&2 || true
      fail "Primary start failed"
    }

  PRIMARY_RUNNING=1
  wait_for_ready "$PRIMARY_PORT" || {
    tail -n 80 "$primary_log" >&2 || true
    fail "Primary is not ready"
  }
}

init_primary_schema() {
  psqlp "$PRIMARY_PORT" -c "CREATE EXTENSION opentde;"
  psqlp "$PRIMARY_PORT" -c "SELECT opentde_set_master_key(decode('$MASTER_HEX','hex'));"
  psqlp "$PRIMARY_PORT" -c "CREATE TABLE t_secure(id int, v text);"
  psqlp "$PRIMARY_PORT" -c "SELECT opentde_enable_table_encryption('t_secure'::regclass);"
  psqlp "$PRIMARY_PORT" -c "INSERT INTO t_secure VALUES (1, 'BASELINE');"
  psqlp "$PRIMARY_PORT" -c "CHECKPOINT;"
  psqlp "$PRIMARY_PORT" -c "SELECT pg_switch_wal();" >/dev/null
}

run_pitr_validation() {
  local pitr_keep_mark
  local pitr_drop_mark
  local target_ts
  local keep_count
  local drop_count

  pitr_keep_mark="PITR_KEEP_$(date +%s)"
  pitr_drop_mark="PITR_DROP_$(date +%s)"

  rm -rf "$PITR_BASE" "$PITR_DATA" "$PITR_RESTORE_TMP"
  mkdir -p "$PITR_RESTORE_TMP"

  "$PG_BASEBACKUP" -h 127.0.0.1 -p "$PRIMARY_PORT" -U postgres -D "$PITR_BASE" -X none >/dev/null

  psqlp "$PRIMARY_PORT" -c "INSERT INTO t_secure VALUES (1001, '$pitr_keep_mark');"
  psqlp "$PRIMARY_PORT" -c "CHECKPOINT;"
  psqlp "$PRIMARY_PORT" -c "SELECT pg_switch_wal();" >/dev/null

  target_ts="$(psqlp_val "$PRIMARY_PORT" "SELECT to_char(clock_timestamp(), 'YYYY-MM-DD HH24:MI:SS.US TZH:TZM')")"
  [[ -n "$target_ts" ]] || fail "Failed to compute PITR target timestamp"

  sleep 1
  psqlp "$PRIMARY_PORT" -c "INSERT INTO t_secure VALUES (1002, '$pitr_drop_mark');"
  psqlp "$PRIMARY_PORT" -c "CHECKPOINT;"
  psqlp "$PRIMARY_PORT" -c "SELECT pg_switch_wal();" >/dev/null

  cp -a "$PITR_BASE" "$PITR_DATA"

  cat >> "$PITR_DATA/postgresql.auto.conf" <<EOF
port = $PITR_PORT
hot_standby = on
restore_command = '$TESTS_DIR/wal_restore_fetch_decrypt.sh "%f" "%p" "http://127.0.0.1:$HTTP_PORT" "$PITR_RESTORE_TMP"'
recovery_target_time = '$target_ts'
recovery_target_action = 'promote'
EOF

  touch "$PITR_DATA/recovery.signal"

  OPENTDE_WAL_ARCHIVE_DIR="$PRIMARY_ARCHIVE_DIR" "$PG_CTL" -D "$PITR_DATA" start -w -l "$WORK_DIR/pitr.log" >/dev/null
  PITR_RUNNING=1

  wait_for_ready "$PITR_PORT" || {
    tail -n 80 "$WORK_DIR/pitr.log" >&2 || true
    fail "PITR instance is not ready"
  }

  keep_count="$(psqlp_val "$PITR_PORT" "SELECT count(*) FROM t_secure WHERE v = '$pitr_keep_mark'")"
  drop_count="$(psqlp_val "$PITR_PORT" "SELECT count(*) FROM t_secure WHERE v = '$pitr_drop_mark'")"

  [[ "$keep_count" == "1" ]] || fail "PITR failed: keep marker not found"
  [[ "$drop_count" == "0" ]] || fail "PITR failed: drop marker should be absent"

  echo "[WAL-PITR-REPL] PITR OK: target recovered, post-target row absent"
}

run_replica_validation() {
  local repl_mark
  local switched_wal
  local replayed
  local i

  repl_mark="REPL_APPLY_$(date +%s)"

  rm -rf "$STANDBY_DATA" "$STANDBY_RESTORE_TMP"
  mkdir -p "$STANDBY_RESTORE_TMP"

  "$PG_BASEBACKUP" -h 127.0.0.1 -p "$PRIMARY_PORT" -U postgres -D "$STANDBY_DATA" -X none >/dev/null

  cat >> "$STANDBY_DATA/postgresql.auto.conf" <<EOF
port = $STANDBY_PORT
hot_standby = on
restore_command = '$TESTS_DIR/wal_restore_fetch_decrypt.sh "%f" "%p" "http://127.0.0.1:$HTTP_PORT" "$STANDBY_RESTORE_TMP"'
recovery_target_timeline = 'latest'
EOF

  touch "$STANDBY_DATA/standby.signal"

  OPENTDE_WAL_ARCHIVE_DIR="$PRIMARY_ARCHIVE_DIR" "$PG_CTL" -D "$STANDBY_DATA" start -w -l "$WORK_DIR/standby.log" >/dev/null
  STANDBY_RUNNING=1

  wait_for_ready "$STANDBY_PORT" || {
    tail -n 80 "$WORK_DIR/standby.log" >&2 || true
    fail "Standby is not ready"
  }

  psqlp "$PRIMARY_PORT" -c "INSERT INTO t_secure VALUES (2001, '$repl_mark');"
  psqlp "$PRIMARY_PORT" -c "CHECKPOINT;"
  switched_wal="$(psqlp_val "$PRIMARY_PORT" "SELECT pg_walfile_name(pg_switch_wal())")"
  [[ -n "$switched_wal" ]] || fail "Failed to switch WAL for replication check"

  for i in {1..60}; do
    replayed="$(psqlp_val "$STANDBY_PORT" "SELECT count(*) FROM t_secure WHERE v = '$repl_mark'" 2>/dev/null || true)"
    if [[ "$replayed" == "1" ]]; then
      break
    fi
    sleep 1
  done

  [[ "$replayed" == "1" ]] || fail "Standby did not apply replicated row from encrypted WAL archive"

  if ! curl -fsS "http://127.0.0.1:$HTTP_PORT/$switched_wal.tde" -o "$NET_SAMPLE_TDE"; then
    fail "Failed to fetch archived encrypted WAL over network"
  fi

  if grep -a -q "$repl_mark" "$NET_SAMPLE_TDE"; then
    fail "Plaintext replication marker leaked in network-transferred .tde archive"
  fi

  "$TESTS_DIR/wal_restore_decrypt.sh" "$switched_wal" "$NET_SAMPLE_DEC" "$PRIMARY_ARCHIVE_DIR"
  if ! grep -a -q "$repl_mark" "$NET_SAMPLE_DEC"; then
    fail "Replication marker not found after decrypting archived WAL"
  fi

  echo "[WAL-PITR-REPL] REPL OK: network transfer contains encrypted .tde, standby decrypts/applies"
}

need_cmd "$INITDB"
need_cmd "$PSQL"
need_cmd "$PG_CTL"
need_cmd "$PG_BASEBACKUP"
need_cmd curl
need_cmd python3

[[ -x "$TESTS_DIR/wal_archive_encrypt.sh" ]] || chmod +x "$TESTS_DIR/wal_archive_encrypt.sh"
[[ -x "$TESTS_DIR/wal_restore_decrypt.sh" ]] || chmod +x "$TESTS_DIR/wal_restore_decrypt.sh"
[[ -x "$TESTS_DIR/wal_restore_fetch_decrypt.sh" ]] || chmod +x "$TESTS_DIR/wal_restore_fetch_decrypt.sh"

mkdir -p "$WORK_DIR"

echo "[WAL-PITR-REPL] Work dir: $WORK_DIR"
start_primary
init_primary_schema
start_http_archive_server
run_pitr_validation
run_replica_validation

echo "[WAL-PITR-REPL] SUCCESS: PITR and archive-shipping replication validated with encrypted WAL transfer"

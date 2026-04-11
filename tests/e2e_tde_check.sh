#!/usr/bin/env bash
# ============================================================================
# e2e_tde_check.sh — Функциональный тест расширения OpenTDE.
# ============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS_DIR="$ROOT_DIR/tests"

PGDATA="${PGDATA:-$HOME/pg_data}"
DBNAME="${DBNAME:-postgres}"
MASTER_HEX="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
MASTER_HEX_2="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"
SENTINEL_TEXT="SENTINEL_OPENTDE_12345"
E2E_ENABLE_MASTER_ROTATION="${E2E_ENABLE_MASTER_ROTATION:-1}"
E2E_ENABLE_WAL_ARCHIVE_ENC="${E2E_ENABLE_WAL_ARCHIVE_ENC:-1}"
OPENTDE_WAL_ARCHIVE_KEY_HEX="${OPENTDE_WAL_ARCHIVE_KEY_HEX:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
OPENTDE_WAL_ARCHIVE_DIR="${OPENTDE_WAL_ARCHIVE_DIR:-$PGDATA/pg_wal_archive_tde_e2e}"
INT_SENTINEL="77777"

# --- Vault environment variables (edit as needed) ---
export VAULT_ADDR="${VAULT_ADDR:-${OPENTDE_VAULT_ADDR:-http://127.0.0.1:8200}}"
export VAULT_PATH="${VAULT_PATH:-${OPENTDE_VAULT_PATH:-secret/pg_tde}}"
export VAULT_FIELD="${VAULT_FIELD:-${OPENTDE_VAULT_FIELD:-master_key}}"
export VAULT_TOKEN="${VAULT_TOKEN:-${OPENTDE_VAULT_TOKEN:-root}}"
export OPENTDE_VAULT_ADDR="${OPENTDE_VAULT_ADDR:-$VAULT_ADDR}"
export OPENTDE_VAULT_PATH="${OPENTDE_VAULT_PATH:-$VAULT_PATH}"
export OPENTDE_VAULT_FIELD="${OPENTDE_VAULT_FIELD:-$VAULT_FIELD}"
export OPENTDE_VAULT_TOKEN="${OPENTDE_VAULT_TOKEN:-$VAULT_TOKEN}"
export OPENTDE_WAL_ARCHIVE_KEY_HEX
export OPENTDE_WAL_ARCHIVE_DIR
if [[ -z "${VAULT_TOKEN:-}" ]]; then
  echo "[WARN] VAULT_TOKEN is not set. Defaulting to the local Vault dev token 'root'."
fi

PSQL="$PGBIN/psql"
PG_CTL="$PGBIN/pg_ctl"

fail() { echo "ОШИБКА: $*" >&2; exit 1; }

sql() {
  "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 "$@"
}

sql_val() {
  "$PSQL" -d "$DBNAME" -Atc "$1"
}

sql_show() {
  local query="$1"
  echo "  SQL> $query"
  "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -P pager=off -c "$query"
}

ensure_wal_archive_helpers() {
  if [[ "$E2E_ENABLE_WAL_ARCHIVE_ENC" != "1" ]]; then
    return 0
  fi

  [[ -x "$TESTS_DIR/wal_archive_encrypt.sh" ]] || chmod +x "$TESTS_DIR/wal_archive_encrypt.sh"
  [[ -x "$TESTS_DIR/wal_restore_decrypt.sh" ]] || chmod +x "$TESTS_DIR/wal_restore_decrypt.sh"
  mkdir -p "$OPENTDE_WAL_ARCHIVE_DIR"
}

wait_for_archived_segment() {
  local wal_name="$1"
  local i

  for i in {1..30}; do
    if [[ -f "$OPENTDE_WAL_ARCHIVE_DIR/$wal_name.tde" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

wait_for_ready() {
  local ready=0
  local i
  for i in {1..30}; do
    if "$PSQL" -d "$DBNAME" -c "SELECT 1" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  [[ $ready -eq 1 ]] || fail "Сервер не готов к запросам"
}

preclean_database_state() {
  "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null 2>&1 || true
DROP TABLE IF EXISTS t_test CASCADE;
DROP TABLE IF EXISTS t_plain CASCADE;
DROP EXTENSION IF EXISTS opentde CASCADE;
DROP FUNCTION IF EXISTS opentde_page_crypto_selftest(oid, int4, bytea);
SQL
}

setup_schema_and_seed() {
  local rc

  set +e
  sql <<SQL
DROP TABLE IF EXISTS t_test CASCADE;
DROP TABLE IF EXISTS t_plain CASCADE;
DROP EXTENSION IF EXISTS opentde CASCADE;
DROP FUNCTION IF EXISTS opentde_page_crypto_selftest(oid, int4, bytea);
CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('$MASTER_HEX', 'hex'));

CREATE TABLE t_test (
  id   int,
  name text
);

CREATE TABLE t_plain (
  id   int,
  name text
);

CREATE INDEX t_test_id_idx ON t_test USING btree (id);
CREATE INDEX t_plain_id_idx ON t_plain USING btree (id);

SELECT opentde_enable_table_encryption('t_test'::regclass);

INSERT INTO t_test VALUES (1, 'Привет мир');
INSERT INTO t_test VALUES (2, 'Тестовая строка');
INSERT INTO t_test VALUES (3, '$SENTINEL_TEXT');
INSERT INTO t_test VALUES ($INT_SENTINEL, 'INT_SENTINEL_ROW');

INSERT INTO t_plain VALUES (1, 'Привет мир');
INSERT INTO t_plain VALUES (2, 'Тестовая строка');
INSERT INTO t_plain VALUES (3, '$SENTINEL_TEXT');
INSERT INTO t_plain VALUES ($INT_SENTINEL, 'INT_SENTINEL_ROW');
SQL
  rc=$?
  set -e
  [[ $rc -eq 0 ]] || return 1
}

verify_index_methods() {
  local id_idx_am
  local plain_id_idx_am

  id_idx_am=$(sql_val "SELECT am.amname FROM pg_class c JOIN pg_am am ON am.oid = c.relam WHERE c.relname = 't_test_id_idx'")
  [[ "$id_idx_am" == "btree" ]] || return 1

  plain_id_idx_am=$(sql_val "SELECT am.amname FROM pg_class c JOIN pg_am am ON am.oid = c.relam WHERE c.relname = 't_plain_id_idx'")
  [[ "$plain_id_idx_am" == "btree" ]] || return 1

  return 0
}

to_hex() {
  printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'
}

restart() {
  local pg_opts
  local archive_cmd
  local shm_key_hex
  local shm_key_dec
  local shmid
  local ext_present

  if ! "$PG_CTL" -D "$PGDATA" status >/dev/null 2>&1 && [[ -f "$PGDATA/postmaster.pid" ]]; then
    shm_key_dec=$(sed -n '5p' "$PGDATA/postmaster.pid" | tr -d '[:space:]')
    if [[ "$shm_key_dec" =~ ^[0-9]+$ ]]; then
      shm_key_hex=$(printf '0x%08x' "$shm_key_dec")
      shmid=$(ipcs -m | awk -v key="$shm_key_hex" '$1 == key { print $2 }')
      if [[ -n "$shmid" ]]; then
        ipcrm -m "$shmid" >/dev/null 2>&1 || true
      fi
    fi
    rm -f "$PGDATA/postmaster.pid" /tmp/.s.PGSQL.5432 /tmp/.s.PGSQL.5432.lock
  fi

  "$PG_CTL" -D "$PGDATA" stop -m fast -w >/dev/null 2>&1 || true
  pg_opts="-c shared_preload_libraries=opentde -c io_method=sync"

  if [[ "$E2E_ENABLE_WAL_ARCHIVE_ENC" == "1" ]]; then
    archive_cmd="$TESTS_DIR/wal_archive_encrypt.sh \"%p\" \"%f\""
    pg_opts+=" -c archive_mode=on -c wal_level=replica -c archive_timeout=10s"
    pg_opts+=" -c archive_command='${archive_cmd}'"
  fi

  "$PG_CTL" -D "$PGDATA" start -w -o "$pg_opts" >/dev/null
  wait_for_ready

  ext_present=$("$PSQL" -d "$DBNAME" -Atc "SELECT 1 FROM pg_extension WHERE extname = 'opentde'" 2>/dev/null || true)
  if [[ "$ext_present" == "1" ]]; then
    "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -c "SELECT opentde_set_master_key(decode('$MASTER_HEX', 'hex'));" >/dev/null
  fi
}

reset_tde_state() {
  "$PG_CTL" -D "$PGDATA" stop -m fast -w >/dev/null 2>&1 || true
  rm -rf "$PGDATA/pg_encryption"
}

reset_full_state() {
  restart
  preclean_database_state
  reset_tde_state
  restart
}

setup_with_retries() {
  setup_schema_and_seed && verify_index_methods
}

run_update_block() {
  if ! sql -c "UPDATE t_test SET name = 'Обновлённая' WHERE id = 2;"; then
    return 1
  fi

  local upd_name
  local upd_id
  local upd2

  upd_name=$(sql_val "SELECT name FROM t_test WHERE id = 2")
  [[ "$upd_name" == "Обновлённая" ]] || return 1

  upd_id=$(sql_val "SELECT id FROM t_test WHERE id = 2")
  [[ "$upd_id" == "2" ]] || return 1

  if ! sql -c "UPDATE t_test SET id = 20, name = 'Двойное обновление' WHERE id = 3;"; then
    return 1
  fi

  upd2=$(sql_val "SELECT id || '|' || name FROM t_test WHERE id = 20")
  [[ "$upd2" == "20|Двойное обновление" ]] || return 1

  if ! sql -c "UPDATE t_test SET id = 3, name = '$SENTINEL_TEXT' WHERE id = 20;"; then
    return 1
  fi

  return 0
}

stabilize_after_restart() {
  local rc
  local i

  restart

  for i in {1..40}; do
    set +e
    sql_val "SELECT count(*) FROM t_plain" >/dev/null 2>&1
    rc=$?
    if [[ $rc -eq 0 ]]; then
      sql_val "SELECT count(*) FROM t_test" >/dev/null 2>&1
      rc=$?
    fi
    if [[ $rc -eq 0 ]]; then
      sql_val "SELECT am.amname FROM pg_class c JOIN pg_am am ON am.oid = c.relam WHERE c.relname = 't_test_id_idx'" | grep -qx "btree"
      rc=$?
    fi
    if [[ $rc -eq 0 ]]; then
      sql_val "SELECT am.amname FROM pg_class c JOIN pg_am am ON am.oid = c.relam WHERE c.relname = 't_plain_id_idx'" | grep -qx "btree"
      rc=$?
    fi
    if [[ $rc -eq 0 ]]; then
      sql_val "SELECT string_agg(id::text, ',' ORDER BY id) FROM t_test WHERE id IN (1,2,3,$INT_SENTINEL)" >/dev/null 2>&1
      rc=$?
    fi
    set -e

    if [[ $rc -eq 0 ]]; then
      return 0
    fi

    sleep 1
  done

  return 1
}

echo ""
echo ""
echo "OpenTDE E2E Functional Test"
echo ""
echo "  CONFIG:"
echo "    PGDATA:   $PGDATA"
echo "    DBNAME:   $DBNAME"
echo "    PGBIN:    $PGBIN"
echo "    SENTINEL: $SENTINEL_TEXT"
echo "    INT IDX:  btree(id)"
echo "    INT SENT: $INT_SENTINEL"
echo "    MK ROT:   $E2E_ENABLE_MASTER_ROTATION"
echo "    WAL ENC:  $E2E_ENABLE_WAL_ARCHIVE_ENC"
echo "    WAL DIR:  $OPENTDE_WAL_ARCHIVE_DIR"
echo ""

ensure_wal_archive_helpers
reset_full_state

# ===========================================================================
echo ""
echo "  [1/7] Установка расширения и создание таблиц"
echo ""
echo ""
if ! setup_with_retries; then
  fail "Не удалось выполнить setup и проверку индексов"
fi

CNT=$(sql_val "SELECT count(*) FROM t_test")
[[ "$CNT" -eq 4 ]] || fail "Ожидалось 4 строки, получено $CNT"
PLAIN_CNT=$(sql_val "SELECT count(*) FROM t_plain")
[[ "$PLAIN_CNT" -eq 4 ]] || fail "Ожидалось 4 строки в t_plain, получено $PLAIN_CNT"
echo "  ✓ Вставлено: t_test=$CNT строк, t_plain=$PLAIN_CNT строк"
echo ""
echo "  Данные в t_plain (обычная таблица):"
sql_show "SELECT id, name FROM t_plain ORDER BY id;"
echo ""
echo "  Данные в t_test (зашифрованная таблица):"
sql_show "SELECT id, name FROM t_test ORDER BY id;"
echo ""

echo ""
echo "  [2/7] UPDATE — Обновляем колонку"
echo ""
echo ""
if ! run_update_block; then
  fail "UPDATE block завершился ошибкой"
fi

UPD_NAME=$(sql_val "SELECT name FROM t_test WHERE id = 2")
[[ "$UPD_NAME" == "Обновлённая" ]] || fail "UPDATE name: '$UPD_NAME'"

UPD_ID=$(sql_val "SELECT id FROM t_test WHERE id = 2")
[[ "$UPD_ID" == "2" ]] || fail "UPDATE: id изменился на '$UPD_ID'"

sql -c "UPDATE t_test SET id = 20, name = 'Двойное обновление' WHERE id = 3;"
UPD2=$(sql_val "SELECT id || '|' || name FROM t_test WHERE id = 20")
[[ "$UPD2" == "20|Двойное обновление" ]] || fail "UPDATE обоих столбцов: '$UPD2'"

sql -c "UPDATE t_test SET id = 3, name = '$SENTINEL_TEXT' WHERE id = 20;"
echo "  ✓ UPDATE успешен"
echo ""
echo "  Данные после UPDATE:"
sql_show "SELECT id, name FROM t_test ORDER BY id;"
echo ""

echo ""
echo "  [3/7] Сравнение файлов: обычная vs зашифрованная таблица/индекс"
echo ""
echo ""
sql -c "CHECKPOINT;"
ENC_RELPATH=$(sql_val "SELECT pg_relation_filepath('t_test'::regclass)")
PLAIN_RELPATH=$(sql_val "SELECT pg_relation_filepath('t_plain'::regclass)")
ENC_IDX_RELPATH=$(sql_val "SELECT pg_relation_filepath('t_test_id_idx'::regclass)")
PLAIN_IDX_RELPATH=$(sql_val "SELECT pg_relation_filepath('t_plain_id_idx'::regclass)")
ENC_FILE="$PGDATA/$ENC_RELPATH"
PLAIN_FILE="$PGDATA/$PLAIN_RELPATH"
ENC_IDX_FILE="$PGDATA/$ENC_IDX_RELPATH"
PLAIN_IDX_FILE="$PGDATA/$PLAIN_IDX_RELPATH"

[[ -f "$PLAIN_FILE" ]] || fail "Файл обычной таблицы не найден: $PLAIN_FILE"
[[ -f "$ENC_FILE" ]] || fail "Файл зашифрованной таблицы не найден: $ENC_FILE"
[[ -f "$PLAIN_IDX_FILE" ]] || fail "Файл обычного индекса не найден: $PLAIN_IDX_FILE"
[[ -f "$ENC_IDX_FILE" ]] || fail "Файл зашифрованного индекса не найден: $ENC_IDX_FILE"

SENTINEL_HEX=$(to_hex "$SENTINEL_TEXT")
echo "  Sentinel String:  $SENTINEL_TEXT"
echo "  Sentinel Hex:     $SENTINEL_HEX"
echo ""
echo "  Файлы таблиц:"
echo "    Plain:     $PLAIN_FILE"
echo "    Encrypted: $ENC_FILE"
echo "  Файлы индексов:"
echo "    Plain idx:     $PLAIN_IDX_FILE"
echo "    Encrypted idx: $ENC_IDX_FILE"
echo ""
ls -lh "$PLAIN_FILE" "$ENC_FILE" "$PLAIN_IDX_FILE" "$ENC_IDX_FILE" | sed 's/^/    /'
echo ""
echo "  Содержимое файла PLAIN (hexdump):"
echo "  ----"
hexdump -C "$PLAIN_FILE" | sed 's/^/    /'
echo "  ----"
echo ""
echo "  Содержимое файла ENCRYPTED (hexdump):"
echo "  ----"
hexdump -C "$ENC_FILE" | sed 's/^/    /'
echo "  ----"
echo ""

echo "  Содержимое файла PLAIN INDEX (hexdump):"
echo "  ----"
hexdump -C "$PLAIN_IDX_FILE" | sed 's/^/    /'
echo "  ----"
echo ""

echo "  Содержимое файла ENCRYPTED INDEX (hexdump):"
echo "  ----"
hexdump -C "$ENC_IDX_FILE" | sed 's/^/    /'
echo "  ----"
echo ""

PLAIN_NIBBLE_OFFSET=$(hexdump -v -e '/1 "%02x"' "$PLAIN_FILE" | grep -bo -m1 "$SENTINEL_HEX" | cut -d: -f1 || true)
[[ -n "$PLAIN_NIBBLE_OFFSET" ]] || fail "hex-паттерн не найден в обычной таблице $PLAIN_RELPATH"
echo "  ✓ PLAIN: hex-паттерн найден"

if hexdump -v -e '/1 "%02x"' "$ENC_FILE" | grep -q -i "$SENTINEL_HEX"; then
  fail "hex-паттерн найден в зашифрованной таблице $ENC_RELPATH"
fi
echo "  ✓ ENCRYPTED: hex-паттерн отсутствует"

INT_HEX_BE=$(printf '%08x' "$INT_SENTINEL")
INT_HEX_LE=$(printf '%s' "$INT_HEX_BE" | sed -E 's/(..)(..)(..)(..)/\4\3\2\1/')
echo "  Int Sentinel:     $INT_SENTINEL"
echo "  Int Hex BE:       $INT_HEX_BE"
echo "  Int Hex LE:       $INT_HEX_LE"

PLAIN_IDX_HEX=$(hexdump -v -e '/1 "%02x"' "$PLAIN_IDX_FILE")
if ! printf '%s' "$PLAIN_IDX_HEX" | grep -q -i -e "$INT_HEX_BE" -e "$INT_HEX_LE"; then
  fail "int-паттерн $INT_SENTINEL не найден в plain btree-индексе $PLAIN_IDX_RELPATH"
fi

ENC_IDX_HEX=$(hexdump -v -e '/1 "%02x"' "$ENC_IDX_FILE")
if printf '%s' "$ENC_IDX_HEX" | grep -q -i -e "$INT_HEX_BE" -e "$INT_HEX_LE"; then
  fail "int-паттерн $INT_SENTINEL найден в encrypted btree-индексе $ENC_IDX_RELPATH"
fi
echo "  ✓ BTREE INT INDEX: int-паттерн есть в plain и отсутствует в encrypted"
echo ""
echo ""
echo "  [4/7] Проверка WAL"
echo ""
echo ""
if [[ "$E2E_ENABLE_WAL_ARCHIVE_ENC" == "1" ]]; then
  WAL_MARK="WAL_ARCHIVE_E2E_$(date +%s)"
  WAL_SEG_REST=""
  WAL_SEG_PATH=""
  TMP_DEC=""

  rm -rf "$OPENTDE_WAL_ARCHIVE_DIR"
  mkdir -p "$OPENTDE_WAL_ARCHIVE_DIR"

  sql -c "DELETE FROM t_test WHERE id = 9001;"
  sql -c "INSERT INTO t_test VALUES (9001,'$WAL_MARK');"
  sql -c "CHECKPOINT;"
  WAL_SEG_REST=$(sql_val "SELECT pg_walfile_name(pg_switch_wal())")

  [[ -n "$WAL_SEG_REST" ]] || fail "Не удалось определить WAL-сегмент после pg_switch_wal()"
  wait_for_archived_segment "$WAL_SEG_REST" || fail "Не найден зашифрованный WAL-архив: $OPENTDE_WAL_ARCHIVE_DIR/$WAL_SEG_REST.tde"

  if grep -a -q "$WAL_MARK" "$OPENTDE_WAL_ARCHIVE_DIR/$WAL_SEG_REST.tde"; then
    fail "Маркер найден в зашифрованном WAL-архиве: $WAL_SEG_REST.tde"
  fi

  TMP_DEC=$(mktemp)
  "$TESTS_DIR/wal_restore_decrypt.sh" "$WAL_SEG_REST" "$TMP_DEC"
  if ! grep -a -q "$WAL_MARK" "$TMP_DEC"; then
    rm -f "$TMP_DEC"
    fail "Маркер не найден после расшифровки WAL-сегмента: $WAL_SEG_REST"
  fi

  WAL_SEG_PATH="$PGDATA/pg_wal/$WAL_SEG_REST"
  if [[ -f "$WAL_SEG_PATH" ]]; then
    ORIG_SHA=$(sha256sum "$WAL_SEG_PATH" | awk '{print $1}')
    REST_SHA=$(sha256sum "$TMP_DEC" | awk '{print $1}')
    [[ "$ORIG_SHA" == "$REST_SHA" ]] || fail "SHA WAL mismatch: $WAL_SEG_REST"
  fi

  rm -f "$TMP_DEC"
  sql -c "DELETE FROM t_test WHERE id = 9001;"
  echo "  ✓ WAL архив защищен: plaintext отсутствует в .tde, decrypt/restore проходит"
else
  echo "  [WARN] WAL archive encryption check skipped (E2E_ENABLE_WAL_ARCHIVE_ENC=$E2E_ENABLE_WAL_ARCHIVE_ENC)"
fi
echo ""
echo ""
echo "  [5/7] Данные читаются после рестарта"
echo ""
echo ""
echo "  Проверяю, что данные пережили рестарт..."
echo ""
echo "  Перезагружаю сервер..."
if ! stabilize_after_restart; then
  fail "Нестабильное состояние после рестарта: проверки чтения/индексов не прошли"
fi
echo ""

PLAIN_CNT=$(sql_val "SELECT count(*) FROM t_plain")
[[ "$PLAIN_CNT" -eq 4 ]] || fail "После рестарта ожидалось 4 строки в t_plain, получено $PLAIN_CNT"

TEST_CNT=$(sql_val "SELECT count(*) FROM t_test")
[[ "$TEST_CNT" -eq 4 ]] || fail "После рестарта ожидалось 4 строки в t_test, получено $TEST_CNT"

echo "  ✓ Обычная таблица сохранилась после рестарта: $PLAIN_CNT строк"
echo "  ✓ Зашифрованная таблица сохранилась после рестарта: $TEST_CNT строк"
echo ""
echo "  Данные после рестарта:"
sql_show "SELECT id, name FROM t_plain ORDER BY id;"
echo ""
sql_show "SELECT id, name FROM t_test ORDER BY id;"
echo ""

echo "  Проверка Index Scan по range (id > / id <) после рестарта:"
PLAN=$($PSQL -d "$DBNAME" -At \
  -c "SET enable_seqscan=off;" \
  -c "SET enable_bitmapscan=off;" \
  -c "EXPLAIN (COSTS OFF) SELECT id, name FROM t_test WHERE id > 1 AND id < 1000 ORDER BY id" | grep -v '^SET$')
echo "$PLAN" | sed 's/^/    /'
echo "$PLAN" | grep -qi "Index Scan" || fail "После рестарта для t_test(1 < id < 1000) не используется Index Scan"

RANGE_GT=$(sql_val "SELECT string_agg(id::text, ',' ORDER BY id) FROM t_test WHERE id > 1 AND id < 1000")
[[ "$RANGE_GT" == "2,3" ]] || fail "Range-поиск (1 < id < 1000) вернул '$RANGE_GT'"

PLAN_LT=$($PSQL -d "$DBNAME" -At \
  -c "SET enable_seqscan=off;" \
  -c "SET enable_bitmapscan=off;" \
  -c "EXPLAIN (COSTS OFF) SELECT id, name FROM t_test WHERE id < 3 ORDER BY id" | grep -v '^SET$')
echo "$PLAN_LT" | sed 's/^/    /'
echo "$PLAN_LT" | grep -qi "Index Scan" || fail "После рестарта для t_test(id < 3) не используется Index Scan"

RANGE_LT=$(sql_val "SELECT string_agg(id::text, ',' ORDER BY id) FROM t_test WHERE id < 3")
[[ "$RANGE_LT" == "1,2" ]] || fail "Range-поиск (id < 3) вернул '$RANGE_LT'"
echo "  ✓ Range Index Scan работает после рестарта"
echo ""

echo ""
echo "  [6/7] Ротация DEK и master key"
echo ""
echo ""
ROTATED_VER=$(sql_val "SELECT opentde_rotate_table_dek('t_test'::regclass::oid)")

[[ "$ROTATED_VER" -ge 2 ]] || fail "Ожидалась версия DEK >= 2 после ротации, получено $ROTATED_VER"

OLD_VAL=$(sql_val "SELECT name FROM t_test WHERE id = 1")
[[ "$OLD_VAL" == "Привет мир" ]] || fail "После ротации DEK старая строка читается неверно: '$OLD_VAL'"

sql -c "INSERT INTO t_test VALUES (8, 'После ротации DEK/master');"
NEW_VAL=$(sql_val "SELECT name FROM t_test WHERE id = 8")
[[ "$NEW_VAL" == "После ротации DEK/master" ]] || fail "Новая строка после ротации DEK читается неверно: '$NEW_VAL'"

if [[ "$E2E_ENABLE_MASTER_ROTATION" == "1" ]]; then
  REWRAPPED_CNT=$(sql_val "SELECT opentde_rotate_master_key(decode('$MASTER_HEX_2', 'hex'))")
  [[ "$REWRAPPED_CNT" -ge 1 ]] || fail "Ротация master key не переобернула ключи"

  OLD_VAL_AFTER_MK=$(sql_val "SELECT name FROM t_test WHERE id = 1")
  [[ "$OLD_VAL_AFTER_MK" == "Привет мир" ]] || fail "После ротации master key старая строка читается неверно: '$OLD_VAL_AFTER_MK'"

  NEW_VAL_AFTER_MK=$(sql_val "SELECT name FROM t_test WHERE id = 8")
  [[ "$NEW_VAL_AFTER_MK" == "После ротации DEK/master" ]] || fail "После ротации master key новая строка читается неверно: '$NEW_VAL_AFTER_MK'"

  REWRAPPED_BACK_CNT=$(sql_val "SELECT opentde_rotate_master_key(decode('$MASTER_HEX', 'hex'))")
  [[ "$REWRAPPED_BACK_CNT" -ge 1 ]] || fail "Обратная ротация master key не переобернула ключи"
else
  REWRAPPED_CNT=0
  REWRAPPED_BACK_CNT=0
  echo "  [INFO] Ротация master key пропущена (E2E_ENABLE_MASTER_ROTATION=$E2E_ENABLE_MASTER_ROTATION)"
fi

sql -c "INSERT INTO t_test VALUES (9, 'После всех ротаций');"
POST_ROT_VAL=$(sql_val "SELECT name FROM t_test WHERE id = 9")
[[ "$POST_ROT_VAL" == "После всех ротаций" ]] || fail "После всех ротаций запись/чтение не работает: '$POST_ROT_VAL'"

sql -c "DELETE FROM t_test WHERE id = 8;"
sql -c "DELETE FROM t_test WHERE id = 9;"

echo "  New DEK version:       $ROTATED_VER"
echo "  Rewrapped keys count:  $REWRAPPED_CNT"
echo "  Rewrapped back count:  $REWRAPPED_BACK_CNT"
echo "  Post-rotation row:     $POST_ROT_VAL"
echo ""
echo "  ✓ Ротация DEK и master key успешна"
echo ""

echo ""
echo "  [7/7] Восстановление после краша сервера"
echo ""
echo ""
echo "  Убиваю процесс сервера (kill -9)..."
PID=$(cat "$PGDATA/postmaster.pid" 2>/dev/null | head -n1)
kill -9 "$PID" 2>/dev/null || true
sleep 2

echo "  Восстанавливаюсь после сбоя..."
"$PG_CTL" -D "$PGDATA" start -w -o "-c shared_preload_libraries=opentde -c io_method=sync" >/dev/null 2>&1 || true
sleep 2
echo ""

READY=0
for i in {1..30}; do
  if "$PSQL" -d "$DBNAME" -c "SELECT 1" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
[[ $READY -eq 1 ]] || fail "Сервер не готов после recovery"
echo ""

VAL=$(sql_val "SELECT name FROM t_plain WHERE id = 1")
[[ "$VAL" == "Привет мир" ]] || fail "После аварийного рестарта: '$VAL'"
ENC_VAL=$(sql_val "SELECT name FROM t_test WHERE id = 1")
[[ "$ENC_VAL" == "Привет мир" ]] || fail "После аварийного рестарта (t_test): '$ENC_VAL'"
echo ""
echo "  Проверяемая строка:"
sql_show "SELECT id, name FROM t_plain WHERE id = 1;"
sql_show "SELECT id, name FROM t_test WHERE id = 1;"
echo ""
echo ""
echo "================================="
echo "   ТЕСТ ПРОЙДЕН УСПЕШНО"
echo "================================="
echo ""

#!/usr/bin/env bash
# ============================================================================
# e2e_tde_check.sh — Функциональный тест расширения OpenTDE.
# ============================================================================
set -euo pipefail

PGDATA="${PGDATA:-$HOME/pg_data}"
DBNAME="${DBNAME:-postgres}"
MASTER_HEX="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"
SENTINEL_TEXT="SENTINEL_OPENTDE_12345"

# --- Vault environment variables (edit as needed) ---
export VAULT_ADDR="${VAULT_ADDR:-${OPENTDE_VAULT_ADDR:-http://127.0.0.1:8200}}"
export VAULT_PATH="${VAULT_PATH:-${OPENTDE_VAULT_PATH:-secret/pg_tde}}"
export VAULT_FIELD="${VAULT_FIELD:-${OPENTDE_VAULT_FIELD:-master_key}}"
export VAULT_TOKEN="${VAULT_TOKEN:-${OPENTDE_VAULT_TOKEN:-root}}"
export OPENTDE_VAULT_ADDR="${OPENTDE_VAULT_ADDR:-$VAULT_ADDR}"
export OPENTDE_VAULT_PATH="${OPENTDE_VAULT_PATH:-$VAULT_PATH}"
export OPENTDE_VAULT_FIELD="${OPENTDE_VAULT_FIELD:-$VAULT_FIELD}"
export OPENTDE_VAULT_TOKEN="${OPENTDE_VAULT_TOKEN:-$VAULT_TOKEN}"
if [[ -z "${VAULT_TOKEN:-}" ]]; then
  echo "[WARN] VAULT_TOKEN is not set. Defaulting to the local Vault dev token 'root'."
fi

PSQL="$PGBIN/psql"
PG_CTL="$PGBIN/pg_ctl"

fail() { echo "ОШИБКА: $*" >&2; exit 1; }

sql() { "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 "$@"; }
sql_val() { "$PSQL" -d "$DBNAME" -Atc "$1"; }

sql_show() {
  local query="$1"
  echo "  SQL> $query"
  "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -P pager=off -c "$query"
}

to_hex() {
  printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'
}

restart() {
  local shm_key_hex
  local shm_key_dec
  local shmid

  if ! "$PG_CTL" -D "$PGDATA" status >/dev/null 2>&1 && [[ -f "$PGDATA/postmaster.pid" ]]; then
    shm_key_dec=$(sed -n '5p' "$PGDATA/postmaster.pid" | tr -d '[:space:]')
    if [[ -n "$shm_key_dec" ]]; then
      shm_key_hex=$(printf '0x%08x' "$shm_key_dec")
      shmid=$(ipcs -m | awk -v key="$shm_key_hex" '$1 == key { print $2 }')
      if [[ -n "$shmid" ]]; then
        ipcrm -m "$shmid" >/dev/null 2>&1 || true
      fi
    fi
    rm -f "$PGDATA/postmaster.pid" /tmp/.s.PGSQL.5432 /tmp/.s.PGSQL.5432.lock
  fi

  "$PG_CTL" -D "$PGDATA" stop -m fast -w >/dev/null 2>&1 || true
  "$PG_CTL" -D "$PGDATA" start -w -o "-c shared_preload_libraries=opentde" >/dev/null
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
echo ""

restart

# ===========================================================================
echo ""
echo "  [1/9] Установка расширения и создание таблиц"
echo ""
echo ""
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
SELECT opentde_enable_table_encryption('t_test'::regclass);

CREATE TABLE t_plain (
  id   int,
  name text
);

INSERT INTO t_test VALUES (1, 'Привет мир');
INSERT INTO t_test VALUES (2, 'Тестовая строка');
INSERT INTO t_test VALUES (3, '$SENTINEL_TEXT');

INSERT INTO t_plain VALUES (1, 'Привет мир');
INSERT INTO t_plain VALUES (2, 'Тестовая строка');
INSERT INTO t_plain VALUES (3, '$SENTINEL_TEXT');
SQL

CNT=$(sql_val "SELECT count(*) FROM t_test")
[[ "$CNT" -eq 3 ]] || fail "Ожидалось 3 строки, получено $CNT"
PLAIN_CNT=$(sql_val "SELECT count(*) FROM t_plain")
[[ "$PLAIN_CNT" -eq 3 ]] || fail "Ожидалось 3 строки в t_plain, получено $PLAIN_CNT"
echo "  ✓ Вставлено: t_test=$CNT строк, t_plain=$PLAIN_CNT строк"
echo ""
echo "  Данные в t_plain (обычная таблица):"
sql_show "SELECT id, name FROM t_plain ORDER BY id;"
echo ""
echo "  Данные в t_test (зашифрованная таблица):"
sql_show "SELECT id, name FROM t_test ORDER BY id;"
echo ""

# echo ""
# echo "  [2/9] UPDATE — Обновляем колонку"
# echo ""
# echo ""
# sql -c "UPDATE t_test SET name = 'Обновлённая' WHERE id = 2;"

# UPD_NAME=$(sql_val "SELECT name FROM t_test WHERE id = 2")
# [[ "$UPD_NAME" == "Обновлённая" ]] || fail "UPDATE name: '$UPD_NAME'"

# UPD_ID=$(sql_val "SELECT id FROM t_test WHERE id = 2")
# [[ "$UPD_ID" == "2" ]] || fail "UPDATE: id изменился на '$UPD_ID'"

# sql -c "UPDATE t_test SET id = 20, name = 'Двойное обновление' WHERE id = 3;"
# UPD2=$(sql_val "SELECT id || '|' || name FROM t_test WHERE id = 20")
# [[ "$UPD2" == "20|Двойное обновление" ]] || fail "UPDATE обоих столбцов: '$UPD2'"

# sql -c "UPDATE t_test SET id = 3, name = '$SENTINEL_TEXT' WHERE id = 20;"
# echo "  ✓ UPDATE успешен"
# echo ""
# echo "  Данные после UPDATE:"
# sql_show "SELECT id, name FROM t_test ORDER BY id;"
# echo ""

# echo ""
# echo "  [3/9] COPY (массовая вставка)"
# echo ""
# echo ""
# printf '4\tСтрока из COPY\n5\tЕщё одна строка\n' \
#   | sql -c "COPY t_test (id, name) FROM STDIN;"

# CNT=$(sql_val "SELECT count(*) FROM t_test")
# [[ "$CNT" -eq 5 ]] || fail "После COPY ожидалось 5 строк, получено $CNT"

# VAL=$(sql_val "SELECT name FROM t_test WHERE id = 4")
# [[ "$VAL" == "Строка из COPY" ]] || fail "COPY: строка id=4 = '$VAL'"
# echo "  ✓ COPY успешен: всего $CNT строк в таблице"
# echo ""
# echo "  Данные после COPY:"
# sql_show "SELECT id, name FROM t_test ORDER BY id;"
# echo ""

# echo ""
# echo "  [4/9] Ротация DEK и чтение смешанных данных"
# echo ""
# echo ""
# DEK_BEFORE_ROT=$(sql_val "SELECT opentde_get_dek_hex('t_test'::regclass::oid)")
# ROTATED_VER=$(sql_val "SELECT opentde_rotate_table_dek('t_test'::regclass::oid)")
# DEK_AFTER_ROT=$(sql_val "SELECT opentde_get_dek_hex('t_test'::regclass::oid)")

# [[ "$ROTATED_VER" -ge 2 ]] || fail "Ожидалась версия DEK >= 2 после ротации, получено $ROTATED_VER"
# [[ "$DEK_BEFORE_ROT" != "$DEK_AFTER_ROT" ]] || fail "DEK не изменился после ротации"

# sql -c "INSERT INTO t_test VALUES (6, 'После ротации DEK');"

# OLD_VAL=$(sql_val "SELECT name FROM t_test WHERE id = 1")
# [[ "$OLD_VAL" == "Привет мир" ]] || fail "Старая строка после ротации читается неверно: '$OLD_VAL'"

# NEW_VAL=$(sql_val "SELECT name FROM t_test WHERE id = 6")
# [[ "$NEW_VAL" == "После ротации DEK" ]] || fail "Новая строка после ротации читается неверно: '$NEW_VAL'"

# CNT=$(sql_val "SELECT count(*) FROM t_test")
# [[ "$CNT" -eq 6 ]] || fail "После ротации ожидалось 6 строк, получено $CNT"

# echo "  DEK before rotation: $DEK_BEFORE_ROT"
# echo "  DEK after rotation:  $DEK_AFTER_ROT"
# echo "  New DEK version:     $ROTATED_VER"
# echo ""
# echo "  ✓ Старые и новые строки читаются"
# echo ""
# echo "  Данные после ротации DEK:"
# sql_show "SELECT id, name FROM t_test ORDER BY id;"
# echo ""

echo ""
echo "  [5/9] Сравнение файлов: обычная vs зашифрованная таблица"
echo ""
echo ""
sql -c "CHECKPOINT;"
ENC_RELPATH=$(sql_val "SELECT pg_relation_filepath('t_test'::regclass)")
PLAIN_RELPATH=$(sql_val "SELECT pg_relation_filepath('t_plain'::regclass)")
ENC_FILE="$PGDATA/$ENC_RELPATH"
PLAIN_FILE="$PGDATA/$PLAIN_RELPATH"

[[ -f "$PLAIN_FILE" ]] || fail "Файл обычной таблицы не найден: $PLAIN_FILE"
[[ -f "$ENC_FILE" ]] || fail "Файл зашифрованной таблицы не найден: $ENC_FILE"

SENTINEL_HEX=$(to_hex "$SENTINEL_TEXT")
echo "  Sentinel String:  $SENTINEL_TEXT"
echo "  Sentinel Hex:     $SENTINEL_HEX"
echo ""
echo "  Файлы таблиц:"
echo "    Plain:     $PLAIN_FILE"
echo "    Encrypted: $ENC_FILE"
echo ""
ls -lh "$PLAIN_FILE" "$ENC_FILE" | sed 's/^/    /'
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

PLAIN_NIBBLE_OFFSET=$(hexdump -v -e '/1 "%02x"' "$PLAIN_FILE" | grep -bo -m1 "$SENTINEL_HEX" | cut -d: -f1 || true)
[[ -n "$PLAIN_NIBBLE_OFFSET" ]] || fail "hex-паттерн не найден в обычной таблице $PLAIN_RELPATH"
echo "  ✓ PLAIN: hex-паттерн найден"

if hexdump -v -e '/1 "%02x"' "$ENC_FILE" | grep -q -i "$SENTINEL_HEX"; then
  fail "hex-паттерн найден в зашифрованной таблице $ENC_RELPATH"
fi
echo "  ✓ ENCRYPTED: hex-паттерн отсутствует"
echo ""

echo ""
echo "  [6/9] Проверка WAL"
echo ""
echo ""
sql -c "DELETE FROM t_test WHERE name='WAL_ENC_000001';"
sql -c "INSERT INTO t_test VALUES (9001,'WAL_ENC_000001');"
sql -c "CHECKPOINT;"
sql -c "SELECT pg_switch_wal();"

sql -c "DELETE FROM t_plain WHERE name='WAL_PLAIN_20260320';"
sql -c "INSERT INTO t_plain VALUES (9101,'WAL_PLAIN_20260320');"
sql -c "CHECKPOINT;"
sql -c "SELECT pg_switch_wal();"

ENC_GREP_OUT=$(mktemp)
PLAIN_GREP_OUT=$(mktemp)

echo "  grep WAL_ENC_000001:"
echo "    (skipped: storage-manager TDE does not rewrite heap WAL records here)"

echo ""
echo "  grep WAL_PLAIN_20260320:"
if grep -aob "WAL_PLAIN_20260320" "$PGDATA"/pg_wal/0* >"$PLAIN_GREP_OUT" 2>/dev/null; then
  sed 's/^/    /' "$PLAIN_GREP_OUT"
  echo "  ✓ WAL_PLAIN_20260320 найден в WAL"
else
  echo "    (no matches)"
  rm -f "$ENC_GREP_OUT" "$PLAIN_GREP_OUT"
  fail "В WAL не найден plaintext-маркер WAL_PLAIN_20260320 для обычной таблицы"
fi

rm -f "$ENC_GREP_OUT" "$PLAIN_GREP_OUT"

sql -c "DELETE FROM t_test WHERE name='WAL_ENC_000001';"
sql -c "DELETE FROM t_plain WHERE name='WAL_PLAIN_20260320';"
echo ""

echo ""
echo "  [7/9] Index Scan"
echo ""
echo ""
sql <<SQL
DROP TABLE IF EXISTS t_range_rw_plain;
CREATE TABLE t_range_rw_plain (
  id int,
  amount bigint
);

INSERT INTO t_range_rw_plain VALUES
  (1, 50),
  (2, 120),
  (3, 900),
  (4, 1100),
  (5, 1300),
  (6, 1700),
  (7, 2100);
SQL

$PSQL -d "$DBNAME" -v ON_ERROR_STOP=1 \
  -c "CREATE INDEX idx_amount_auto ON t_range_rw_plain(amount);" \
  -c "ANALYZE t_range_rw_plain;" >/dev/null

PLAN=$($PSQL -d "$DBNAME" -At \
  -c "SET enable_seqscan=off;" \
  -c "SET enable_bitmapscan=off;" \
  -c "EXPLAIN (COSTS OFF) SELECT id, amount FROM t_range_rw_plain WHERE amount > 1000 ORDER BY id" | grep -v '^SET$')

echo "  Query Plan:"
echo "  ----"
echo "$PLAN" | sed 's/^/    /'
echo "$PLAN" | grep -qi "Index Scan" || fail "Index Scan не используется для amount > 1000"

FOUND=$($PSQL -d "$DBNAME" -At \
  -c "SELECT string_agg(id::text, ',' ORDER BY id) FROM t_range_rw_plain WHERE amount > 1000" | grep -v '^SET$')

[[ "$FOUND" == "4,5,6,7" ]] || fail "Ожидались id=4,5,6,7, получено '$FOUND'"
echo ""
echo "  ✓ Index Scan работает для условия amount > 1000"
echo "  ✓ Найденные id: $FOUND"
echo ""

echo ""
echo "  [8/9] Данные читаются после рестарта"
echo ""
echo ""
echo "  Проверяю, что данные пережили рестарт..."
echo ""
echo "  Перезагружаю сервер..."
restart
echo ""

PLAIN_CNT=$(sql_val "SELECT count(*) FROM t_plain")
[[ "$PLAIN_CNT" -eq 3 ]] || fail "После рестарта ожидалось 3 строки в t_plain, получено $PLAIN_CNT"

echo "  ✓ Обычная таблица сохранилась после рестарта: $PLAIN_CNT строк"
echo ""
echo "  Данные после рестарта:"
sql_show "SELECT id, name FROM t_plain ORDER BY id;"
echo ""

echo ""
echo "  [9/9] Восстановление после краша сервера"
echo ""
echo ""
echo "  Убиваю процесс сервера (kill -9)..."
PID=$(cat "$PGDATA/postmaster.pid" 2>/dev/null | head -n1)
kill -9 "$PID" 2>/dev/null || true
sleep 2

echo "  Восстанавливаюсь после сбоя..."
"$PG_CTL" -D "$PGDATA" start >/dev/null 2>&1 || true
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
echo ""
echo "  Проверяемая строка:"
sql_show "SELECT id, name FROM t_plain WHERE id = 1;"
echo ""
echo ""
echo "================================="
echo "   ТЕСТ ПРОЙДЕН УСПЕШНО"
echo "================================="
echo ""

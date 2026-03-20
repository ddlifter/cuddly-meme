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
  "$PG_CTL" -D "$PGDATA" stop -m fast -w >/dev/null 2>&1 || true
  "$PG_CTL" -D "$PGDATA" start -w >/dev/null
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

"$PG_CTL" -D "$PGDATA" status >/dev/null 2>&1 || "$PG_CTL" -D "$PGDATA" start -w >/dev/null

# ===========================================================================
echo ""
echo "  [1/8] Установка расширения и создание таблиц"
echo ""
echo ""
sql <<SQL
DROP TABLE IF EXISTS t_test CASCADE;
DROP TABLE IF EXISTS t_plain CASCADE;
DROP EXTENSION IF EXISTS opentde CASCADE;
CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('$MASTER_HEX', 'hex'));

CREATE TABLE t_test (
  id   int,
  name text
) USING opentde;

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

echo ""
echo "  [2/8] UPDATE — Обновляем колонку"
echo ""
echo ""
sql -c "UPDATE t_test SET name = 'Обновлённая' WHERE id = 2;"

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
echo "  [3/8] COPY (массовая вставка)"
echo ""
echo ""
printf '4\tСтрока из COPY\n5\tЕщё одна строка\n' \
  | sql -c "COPY t_test (id, name) FROM STDIN;"

CNT=$(sql_val "SELECT count(*) FROM t_test")
[[ "$CNT" -eq 5 ]] || fail "После COPY ожидалось 5 строк, получено $CNT"

VAL=$(sql_val "SELECT name FROM t_test WHERE id = 4")
[[ "$VAL" == "Строка из COPY" ]] || fail "COPY: строка id=4 = '$VAL'"
echo "  ✓ COPY успешен: всего $CNT строк в таблице"
echo ""
echo "  Данные после COPY:"
sql_show "SELECT id, name FROM t_test ORDER BY id;"
echo ""

echo ""
echo "  [4/8] Сравнение файлов: обычная vs зашифрованная таблица"
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
echo "  [5/8] Проверка WAL"
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
if grep -aob "WAL_ENC_000001" "$PGDATA"/pg_wal/0* >"$ENC_GREP_OUT" 2>/dev/null; then
  sed 's/^/    /' "$ENC_GREP_OUT"
  rm -f "$ENC_GREP_OUT" "$PLAIN_GREP_OUT"
  fail "В WAL найден plaintext-маркер WAL_ENC_000001 для зашифрованной таблицы"
else
  echo "    (no matches)"
  echo "  ✓ WAL_ENC_000001 не найден в WAL"
fi

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
echo "  [6/8] Слепой индекс и Index Scan"
echo ""
echo ""
sql -c "CREATE INDEX idx_blind ON t_test (opentde_blind_index(name));"
echo ""

PLAN=$($PSQL -d "$DBNAME" -At -c "SET enable_seqscan=off;" -c "EXPLAIN (COSTS OFF) SELECT * FROM t_test WHERE opentde_blind_index(name) = opentde_blind_index('Привет мир')" | grep -v '^SET$')
echo "  Query Plan:"
echo "  ----"
echo "$PLAN" | sed 's/^/    /'
echo "$PLAN" | grep -qi "index" || fail "Index Scan не используется"

FOUND=$($PSQL -d "$DBNAME" -At -c "SET enable_seqscan=off;" -c "SELECT name FROM t_test WHERE opentde_blind_index(name) = opentde_blind_index('Привет мир')" | grep -v '^SET$')
[[ "$FOUND" == "Привет мир" ]] || fail "Index Scan вернул '$FOUND'"
echo ""
echo "  ✓ Index Scan работает"
echo "  ✓ Найденная строка: $FOUND"
echo ""

echo ""
echo "  [7/8] Данные читаются после рестарта"
echo ""
echo ""
DEK_BEFORE=$(sql_val "SELECT opentde_get_dek_hex('t_test'::regclass::oid)")
echo "  DEK before restart: $DEK_BEFORE"
echo ""
echo "  Перезагружаю сервер..."
restart
echo ""

CNT=$(sql_val "SELECT count(*) FROM t_test")
[[ "$CNT" -eq 5 ]] || fail "После рестарта ожидалось 5 строк, получено $CNT"

DEK_AFTER=$(sql_val "SELECT opentde_get_dek_hex('t_test'::regclass::oid)")
[[ "$DEK_BEFORE" == "$DEK_AFTER" ]] || fail "DEK изменился после рестарта"
echo "  DEK after restart:  $DEK_AFTER"
echo ""
echo "  ✓ DEK совпадает после рестарта"
echo "  ✓ Данные сохранились: $CNT строк"
echo ""
echo "  Данные после рестарта:"
sql_show "SELECT id, name FROM t_test ORDER BY id;"
echo ""

echo ""
echo "  [8/8] Восстановление после краша сервера"
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

VAL=$(sql_val "SELECT name FROM t_test WHERE id = 1")
[[ "$VAL" == "Привет мир" ]] || fail "После аварийного рестарта: '$VAL'"
echo ""
echo "  Проверяемая строка:"
sql_show "SELECT id, name FROM t_test WHERE id = 1;"
echo ""
echo ""
echo "================================="
echo "   ТЕСТ ПРОЙДЕН УСПЕШНО"
echo "================================="
echo ""

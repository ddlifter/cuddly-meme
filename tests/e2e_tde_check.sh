#!/usr/bin/env bash
# ============================================================================
# e2e_tde_check.sh — Сквозной тест расширения OpenTDE.
#
# Проверяет:
#   1. Установка расширения и мастер-ключа
#   2. INSERT / SELECT для типов int и text
#   3. UPDATE — изменённые и неизменённые столбцы корректны
#   4. COPY (массовая вставка через multi_insert)
#   5. Шифрование на диске (sentinel не виден в strings)
#   6. Слепой индекс (blind index) и Index Scan
#   7. Сохранение данных и DEK после рестарта
#   8. Восстановление после аварийной остановки (immediate stop)
#   9. Права доступа к файлам ключей (0600)
#
# Использование:
#   chmod +x tests/e2e_tde_check.sh
#   tests/e2e_tde_check.sh
# ============================================================================
set -euo pipefail

# --- Настройки ---
PGDATA="${PGDATA:-$HOME/pg_data}"
DBNAME="${DBNAME:-postgres}"
MASTER_HEX="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"

PSQL="$PGBIN/psql"
PG_CTL="$PGBIN/pg_ctl"

fail() { echo "ПРОВАЛ: $*" >&2; exit 1; }

sql() { "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 "$@"; }
sql_val() { "$PSQL" -d "$DBNAME" -Atc "$1"; }

restart() {
  "$PG_CTL" -D "$PGDATA" stop -m fast -w >/dev/null 2>&1 || true
  "$PG_CTL" -D "$PGDATA" start -w >/dev/null
}

# Убедиться, что сервер запущен
"$PG_CTL" -D "$PGDATA" status >/dev/null 2>&1 || "$PG_CTL" -D "$PGDATA" start -w >/dev/null

# ===========================================================================
echo "[1/8] Установка расширения и создание таблицы"
# ===========================================================================
sql <<SQL
DROP EXTENSION IF EXISTS opentde CASCADE;
CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('$MASTER_HEX', 'hex'));

CREATE TABLE t_test (
  id   int,
  name text
) USING opentde;

INSERT INTO t_test VALUES (1, 'Привет мир');
INSERT INTO t_test VALUES (2, 'Тестовая строка');
INSERT INTO t_test VALUES (3, 'SENTINEL_OPENTDE');
SQL

CNT=$(sql_val "SELECT count(*) FROM t_test")
[[ "$CNT" -eq 3 ]] || fail "Ожидалось 3 строки, получено $CNT"
echo "  OK: вставлено $CNT строк"

# ===========================================================================
echo "[2/8] UPDATE — изменённые и неизменённые столбцы"
# ===========================================================================
sql -c "UPDATE t_test SET name = 'Обновлённая' WHERE id = 2;"

UPD_NAME=$(sql_val "SELECT name FROM t_test WHERE id = 2")
[[ "$UPD_NAME" == "Обновлённая" ]] || fail "UPDATE name: '$UPD_NAME'"

UPD_ID=$(sql_val "SELECT id FROM t_test WHERE id = 2")
[[ "$UPD_ID" == "2" ]] || fail "UPDATE: id изменился на '$UPD_ID'"

sql -c "UPDATE t_test SET id = 20, name = 'Двойное обновление' WHERE id = 3;"
UPD2=$(sql_val "SELECT id || '|' || name FROM t_test WHERE id = 20")
[[ "$UPD2" == "20|Двойное обновление" ]] || fail "UPDATE обоих столбцов: '$UPD2'"

# Вернуть id=3 обратно для остальных тестов
sql -c "UPDATE t_test SET id = 3, name = 'SENTINEL_OPENTDE' WHERE id = 20;"
echo "  OK: UPDATE корректен"

# ===========================================================================
echo "[3/8] COPY (массовая вставка)"
# ===========================================================================
printf '4\tСтрока из COPY\n5\tЕщё одна строка\n' \
  | sql -c "COPY t_test (id, name) FROM STDIN;"

CNT=$(sql_val "SELECT count(*) FROM t_test")
[[ "$CNT" -eq 5 ]] || fail "После COPY ожидалось 5 строк, получено $CNT"

VAL=$(sql_val "SELECT name FROM t_test WHERE id = 4")
[[ "$VAL" == "Строка из COPY" ]] || fail "COPY: строка id=4 = '$VAL'"
echo "  OK: COPY — всего $CNT строк"

# ===========================================================================
echo "[4/8] Данные зашифрованы на диске"
# ===========================================================================
sql -c "CHECKPOINT;"
RELPATH=$(sql_val "SELECT pg_relation_filepath('t_test'::regclass)")

if strings "$PGDATA/$RELPATH" | grep -q 'SENTINEL_OPENTDE'; then
  fail "Открытый текст виден в файле $RELPATH"
fi
echo "  OK: sentinel не найден в файле данных"

# ===========================================================================
echo "[5/8] Слепой индекс и Index Scan"
# ===========================================================================
sql -c "CREATE INDEX idx_blind ON t_test (opentde_blind_index(name));"

PLAN=$($PSQL -d "$DBNAME" -At -c "SET enable_seqscan=off;" -c "EXPLAIN (COSTS OFF) SELECT * FROM t_test WHERE opentde_blind_index(name) = opentde_blind_index('Привет мир')" | grep -v '^SET$')
echo "$PLAN" | grep -qi "index" || fail "Index Scan не используется"

FOUND=$($PSQL -d "$DBNAME" -At -c "SET enable_seqscan=off;" -c "SELECT name FROM t_test WHERE opentde_blind_index(name) = opentde_blind_index('Привет мир')" | grep -v '^SET$')
[[ "$FOUND" == "Привет мир" ]] || fail "Index Scan вернул '$FOUND'"
echo "  OK: Index Scan нашёл правильную строку"

# ===========================================================================
echo "[6/8] Данные читаются после рестарта, DEK стабилен"
# ===========================================================================
DEK_BEFORE=$(sql_val "SELECT opentde_get_dek_hex('t_test'::regclass::oid)")
restart

CNT=$(sql_val "SELECT count(*) FROM t_test")
[[ "$CNT" -eq 5 ]] || fail "После рестарта ожидалось 5 строк, получено $CNT"

DEK_AFTER=$(sql_val "SELECT opentde_get_dek_hex('t_test'::regclass::oid)")
[[ "$DEK_BEFORE" == "$DEK_AFTER" ]] || fail "DEK изменился после рестарта"
echo "  OK: $CNT строк, DEK стабилен"

# ===========================================================================
echo "[7/8] Восстановление после аварийной остановки"
# ===========================================================================
"$PG_CTL" -D "$PGDATA" stop -m immediate >/dev/null
"$PG_CTL" -D "$PGDATA" start -w >/dev/null

VAL=$(sql_val "SELECT name FROM t_test WHERE id = 1")
[[ "$VAL" == "Привет мир" ]] || fail "После аварийного рестарта: '$VAL'"
echo "  OK: данные корректны после аварийной остановки"

# ===========================================================================
echo "[8/8] Файлы ключей существуют с правами 0600"
# ===========================================================================
for f in master.key keys ivs; do
  FILE="$PGDATA/pg_encryption/$f"
  [[ -f "$FILE" ]] || fail "Файл не найден: $FILE"
  MODE=$(stat -c '%a' "$FILE")
  [[ "$MODE" == "600" ]] || fail "$f: права $MODE, ожидалось 600"
done
echo "  OK: все файлы на месте"

echo ""
echo "=== ТЕСТ ПРОЙДЕН ==="

#!/usr/bin/env bash
# Crash-test for OpenTDE pagestore: update/delete + forced restart
set -euo pipefail

PGDATA="${PGDATA:-$HOME/pg_data}"
DBNAME="${DBNAME:-postgres}"
PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"
PSQL="$PGBIN/psql"
PG_CTL="$PGBIN/pg_ctl"

fail() { echo "ОШИБКА: $*" >&2; exit 1; }

restart() {
  "$PG_CTL" -D "$PGDATA" stop -m fast -w >/dev/null 2>&1 || true
  "$PG_CTL" -D "$PGDATA" start -w >/dev/null
}

# 1. Setup
"$PG_CTL" -D "$PGDATA" status >/dev/null 2>&1 || "$PG_CTL" -D "$PGDATA" start -w >/dev/null

$PSQL -d "$DBNAME" -v ON_ERROR_STOP=1 <<SQL
DROP TABLE IF EXISTS t_crash CASCADE;
CREATE TABLE t_crash (id int, val text) USING opentde_page;
INSERT INTO t_crash VALUES (1, 'one'), (2, 'two'), (3, 'three');
SQL

CNT=$($PSQL -d "$DBNAME" -Atc "SELECT count(*) FROM t_crash")
[[ "$CNT" -eq 3 ]] || fail "Ожидалось 3 строки, получено $CNT"
echo "✓ Исходные данные: $CNT строк"

# 2. Update, but crash before checkpoint
$PSQL -d "$DBNAME" -c "UPDATE t_crash SET val = 'ONE' WHERE id = 1;"
$PSQL -d "$DBNAME" -c "DELETE FROM t_crash WHERE id = 2;"
echo "✓ UPDATE и DELETE выполнены"

# 3. Simulate crash (kill -9)
PID=$(cat "$PGDATA/postmaster.pid" 2>/dev/null | head -n1)
kill -9 "$PID" 2>/dev/null || true
sleep 2

# 4. Restart and check
"$PG_CTL" -D "$PGDATA" start >/dev/null 2>&1 || true
sleep 2
READY=0
for i in {1..30}; do
  if "$PSQL" -d "$DBNAME" -c "SELECT 1" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
[[ $READY -eq 1 ]] || fail "Сервер не готов после recovery"

VAL1=$($PSQL -d "$DBNAME" -Atc "SELECT val FROM t_crash WHERE id = 1")
[[ "$VAL1" == "ONE" ]] || fail "UPDATE не сохранился после краша: $VAL1"
CNT2=$($PSQL -d "$DBNAME" -Atc "SELECT count(*) FROM t_crash")
[[ "$CNT2" -eq 2 ]] || fail "DELETE не сохранился после краша: осталось $CNT2 строк"
echo "✓ UPDATE/DELETE корректно восстановлены после аварии"

# 5. Cleanup
$PSQL -d "$DBNAME" -c "DROP TABLE IF EXISTS t_crash;"
echo "Тест завершён успешно."

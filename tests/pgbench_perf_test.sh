#!/usr/bin/env bash
# ============================================================================
# pgbench_perf_test.sh — Тест производительности OpenTDE vs обычная таблица
# ============================================================================
# Сравнивает производительность зашифрованных и обычных таблиц в PostgreSQL
# 
# Использование:
#   ./pgbench_perf_test.sh [DBNAME] [PGBIN]
#
# Примеры:
#   ./pgbench_perf_test.sh postgres ~/diploma/pg_build/bin
#   ./pgbench_perf_test.sh testdb
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DBNAME="${1:-postgres}"
PGBIN="${2:-$HOME/diploma/pg_build/bin}"
PGDATA="${PGDATA:-$HOME/pg_data}"

PSQL="$PGBIN/psql"
PGBENCH="$PGBIN/pgbench"
PG_CTL="$PGBIN/pg_ctl"

# Параметры тестирования
CLIENTS=1
THREADS=1
DURATION=3   # секунд для каждого теста
ROWS="${ROWS:-1000000}"
BATCH_SIZE="${BATCH_SIZE:-10000}"

RESULTS_DIR="${SCRIPT_DIR}/pgbench_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="${RESULTS_DIR}/perf_report_${TIMESTAMP}.txt"

# ============================================================================
# Функции
# ============================================================================

log() { echo "[$(date '+%H:%M:%S')] $*"; }
fail() { echo "ОШИБКА: $*" >&2; exit 1; }

sql() { "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 "$@"; }
sql_val() { "$PSQL" -d "$DBNAME" -Atc "$1"; }

check_postgres() {
  if ! "$PG_CTL" -D "$PGDATA" status >/dev/null 2>&1; then
    log "PostgreSQL не запущен, запускаю..."
    "$PG_CTL" -D "$PGDATA" start -w >/dev/null || fail "Не могу запустить PostgreSQL"
  fi
  log "✓ PostgreSQL запущен"
}

load_data_in_batches() {
  local start_id=1
  local end_id=0
  local loaded=0

  log "Заполняю таблицы батчами: rows=$ROWS, batch=$BATCH_SIZE"

  while [[ "$start_id" -le "$ROWS" ]]; do
    end_id=$((start_id + BATCH_SIZE - 1))
    if [[ "$end_id" -gt "$ROWS" ]]; then
      end_id=$ROWS
    fi

    sql -c "INSERT INTO t_encrypted (id, name, balance)
            SELECT i, 'user_' || i, (i % 10000)::integer
            FROM generate_series($start_id, $end_id) AS i;" >/dev/null

    sql -c "INSERT INTO t_plain (id, name, balance)
            SELECT i, 'user_' || i, (i % 10000)::integer
            FROM generate_series($start_id, $end_id) AS i;" >/dev/null

    loaded=$end_id
    if (( loaded % (BATCH_SIZE * 10) == 0 )) || [[ "$loaded" -eq "$ROWS" ]]; then
      log "  Загружено строк: $loaded / $ROWS"
    fi

    start_id=$((end_id + 1))
  done
}

collect_pgbench_result() {
  local script_file="$1"
  local output=""
  local metrics=""
  local errors=""

  output=$("$PGBENCH" \
    -n \
    -d "$DBNAME" \
    -c "$CLIENTS" \
    -j "$THREADS" \
    -f "$script_file" \
    -T "$DURATION" \
    2>&1 || true)

  metrics=$(printf '%s\n' "$output" | grep -E "latency average|tps =" || true)
  errors=$(printf '%s\n' "$output" | grep -E "missing tuple IV|ERROR:|FATAL:|server closed the connection unexpectedly|connection to server was lost|Run was aborted" | head -3 || true)

  if [[ -n "$metrics" ]]; then
    printf '%s' "$metrics"
    if [[ -n "$errors" ]]; then
      printf '\n%s' "$errors"
    fi
    return
  fi

  if [[ -n "$errors" ]]; then
    printf '%s' "$errors"
    return
  fi

  printf 'error'
}

# ============================================================================
# Основная программа
# ============================================================================

mkdir -p "$RESULTS_DIR"

log "=========================================================================="
log "OpenTDE pgbench Performance Test"
log "=========================================================================="
log "Database:    $DBNAME"
log "PGBIN:       $PGBIN"
log "Clients:     $CLIENTS"
log "Threads:     $THREADS"
log "Duration:    ${DURATION}s"
log "Rows:        $ROWS"
log "Batch size:  $BATCH_SIZE"
log "Results dir: $RESULTS_DIR"
log ""

# Проверяем PostgreSQL
check_postgres

# Подключаемся к БД
log "Подключаюсь к $DBNAME..."
if ! "$PSQL" -d "$DBNAME" -c "SELECT 1" >/dev/null 2>&1; then
  fail "Не могу подключиться к $DBNAME"
fi
log "✓ Подключение успешно"
log ""

# ============================================================================
# Подготовка: создание таблиц и загрузка данных
# ============================================================================

log "=========================================================================="
log "Этап 1: Подготовка (создание таблиц, загрузка данных)"
log "=========================================================================="

START_TIME=$(date +%s)

log "Создаю таблицы..."
sql -f "${SCRIPT_DIR}/pgbench_setup.sql" | tail -5

load_data_in_batches

END_TIME=$(date +%s)
SETUP_TIME=$((END_TIME - START_TIME))
log "✓ Подготовка завершена (${SETUP_TIME}s)"

# Получить размеры таблиц
ENC_SIZE=$(sql_val "SELECT pg_size_pretty(pg_total_relation_size('t_encrypted')) FROM pg_class WHERE relname='t_encrypted'")
PLAIN_SIZE=$(sql_val "SELECT pg_size_pretty(pg_total_relation_size('t_plain')) FROM pg_class WHERE relname='t_plain'")

log ""
log "Размер таблиц:"
log "  t_encrypted: $ENC_SIZE"
log "  t_plain:     $PLAIN_SIZE"
log ""

# ============================================================================
# Тестирование
# ============================================================================

log "=========================================================================="
log "Этап 2: Тесты производительности"
log "=========================================================================="
log ""

# Инициализируем отчет
{
  echo "============================================================================"
  echo "OpenTDE Performance Report"
  echo "============================================================================"
  echo "Generated: $(date)"
  echo "Database:  $DBNAME"
  echo "Clients:   $CLIENTS"
  echo "Threads:   $THREADS"
  echo "Duration:  ${DURATION}s"
  echo ""
  echo "Table Sizes:"
  echo "  t_encrypted: $ENC_SIZE"
  echo "  t_plain:     $PLAIN_SIZE"
  echo "============================================================================"
  echo ""
} > "$REPORT"

run_test() {
  local test_name="$1"
  local script_encrypted="$2"
  local script_plain="$3"
  local label="$4"

  log "Test: $test_name ($label)"
  log "  Encrypted: $script_encrypted"
  log "  Plain:     $script_plain"
  log ""

  log "  Запускаю тест на plain..."
  check_postgres
  PLAIN_RESULT=$(collect_pgbench_result "${SCRIPT_DIR}/${script_plain}")

  # Тест зашифрованной таблицы
  log "  Запускаю тест на encrypted..."
  check_postgres
  ENC_RESULT=$(collect_pgbench_result "${SCRIPT_DIR}/${script_encrypted}")

  # Печатаю результаты
  echo ""
  echo "═══════════════════════════════════════════════════════════════════════════"
  echo "Test: $test_name ($label)"
  echo "═══════════════════════════════════════════════════════════════════════════"
  echo ""
  echo "ENCRYPTED TABLE:"
  echo "$ENC_RESULT"
  echo ""
  echo "PLAIN TABLE:"
  echo "$PLAIN_RESULT"
  echo ""

  # Сохраняю в отчет
  {
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo "Test: $test_name ($label)"
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "ENCRYPTED TABLE:"
    echo "$ENC_RESULT"
    echo ""
    echo "PLAIN TABLE:"
    echo "$PLAIN_RESULT"
    echo ""
  } >> "$REPORT"
}

# === Test 1: Read-Only ===
run_test "Read-Only" \
  "pgbench_readonly_encrypted.sql" \
  "pgbench_readonly_plain.sql" \
  "СЕЛЕКТы (точечные чтения)"

# === Test 2: Write ===
run_test "Write" \
  "pgbench_write_encrypted.sql" \
  "pgbench_write_plain.sql" \
  "INSERT"

# ============================================================================
# Итоги
# ============================================================================

log ""
log "=========================================================================="
log "Тестирование завершено"
log "=========================================================================="
log "Отчет сохранен в: $REPORT"
log ""
log "Содержимое отчета:"
cat "$REPORT"

log ""
log "✓ Все тесты завершены"


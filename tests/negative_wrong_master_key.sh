#!/usr/bin/env bash
# ============================================================================
# negative_wrong_master_key.sh — Негативный тест: подмена мастер-ключа.
#
# Проверяет, что при неправильном мастер-ключе данные НЕ расшифровываются
# корректно (запрос либо падает с ошибкой, либо возвращает мусор).
#
# После теста оригинальный ключ автоматически восстанавливается (trap).
#
# Использование:
#   chmod +x tests/negative_wrong_master_key.sh
#   tests/negative_wrong_master_key.sh
# ============================================================================
set -euo pipefail

# --- Настройки ---
PGDATA="${PGDATA:-$HOME/pg_data}"
DBNAME="${DBNAME:-postgres}"
PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"

PSQL="$PGBIN/psql"
PG_CTL="$PGBIN/pg_ctl"

MASTER_FILE="$PGDATA/pg_encryption/master.key"
BACKUP_FILE="$MASTER_FILE.bak_test"

fail() { echo "ПРОВАЛ: $*" >&2; exit 1; }

restart() {
  "$PG_CTL" -D "$PGDATA" stop -m fast -w >/dev/null 2>&1 || true
  "$PG_CTL" -D "$PGDATA" start -w >/dev/null
}

# Автоматическое восстановление оригинального ключа при выходе
cleanup() {
  if [[ -f "$BACKUP_FILE" ]]; then
    cp "$BACKUP_FILE" "$MASTER_FILE"
    chmod 600 "$MASTER_FILE"
    rm -f "$BACKUP_FILE"
    restart || true
  fi
}
trap cleanup EXIT

# --- Предусловия ---
[[ -f "$MASTER_FILE" ]] || fail "Файл мастер-ключа не найден: $MASTER_FILE"
cp "$MASTER_FILE" "$BACKUP_FILE"
chmod 600 "$BACKUP_FILE"

# ===========================================================================
echo "[1/3] Подмена мастер-ключа случайными байтами и рестарт"
# ===========================================================================
head -c 32 /dev/urandom > "$MASTER_FILE"
chmod 600 "$MASTER_FILE"
restart

# ===========================================================================
echo "[2/3] Попытка прочитать зашифрованные данные"
# ===========================================================================
set +e
RESULT=$("$PSQL" -d "$DBNAME" -Atc "SELECT name FROM t_test WHERE id = 1" 2>&1)
STATUS=$?
set -e

# ===========================================================================
echo "[3/3] Проверка: данные НЕ расшифровались правильно"
# ===========================================================================
if [[ $STATUS -ne 0 ]]; then
  echo "  OK: запрос упал с ошибкой (ожидаемое поведение)"
  echo ""
  echo "=== ТЕСТ ПРОЙДЕН ==="
  exit 0
fi

if [[ "$RESULT" == "Привет мир" ]]; then
  fail "Данные расшифровались правильно с неверным ключом!"
fi

echo "  OK: запрос вернул мусор вместо исходного текста"
echo ""
echo "=== ТЕСТ ПРОЙДЕН ==="

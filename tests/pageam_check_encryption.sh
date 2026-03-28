#!/usr/bin/env bash
set -euo pipefail

DBNAME="${1:-postgres}"
PGBIN="${2:-$HOME/diploma/pg_build/bin}"
PGDATA="${PGDATA:-$HOME/pg_data}"

PSQL="$PGBIN/psql"
MARKER="secret_pageam_row_777"

ENC_REL_PATH=$($PSQL -d "$DBNAME" -Atc "SELECT pg_relation_filepath('t_page_enc');")
PLAIN_REL_PATH=$($PSQL -d "$DBNAME" -Atc "SELECT pg_relation_filepath('t_page_plain');")

ENC_FILE="$PGDATA/$ENC_REL_PATH"
PLAIN_FILE="$PGDATA/$PLAIN_REL_PATH"

echo "[check] marker: $MARKER"
echo "[check] enc file: $ENC_FILE"
echo "[check] plain file: $PLAIN_FILE"

echo "[check] plaintext marker in plain file:"
if strings "$PLAIN_FILE" | grep -q "$MARKER"; then
  echo "  FOUND (expected)"
else
  echo "  NOT FOUND (unexpected)"
fi

echo "[check] plaintext marker in encrypted file:"
if strings "$ENC_FILE" | grep -q "$MARKER"; then
  echo "  FOUND (unexpected, not encrypted effectively)"
else
  echo "  NOT FOUND (expected)"
fi

echo "[check] hexdump preview plain:"
hexdump -C "$PLAIN_FILE" | head -n 8 || true

echo "[check] hexdump preview enc:"
hexdump -C "$ENC_FILE" | head -n 8 || true

echo "[check] transparency query (should return row):"
$PSQL -d "$DBNAME" -c "SELECT id, payload FROM t_page_enc WHERE id = 777;"

#!/usr/bin/env bash
set -euo pipefail

DBNAME="${1:-postgres}"
PGBIN="${2:-$HOME/diploma/pg_build/bin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PSQL="$PGBIN/psql"
PGBENCH="$PGBIN/pgbench"

CLIENTS=1
THREADS=1
DURATION=5

echo "[pageam] setup..."
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -f "$SCRIPT_DIR/pageam_1k_setup.sql"

echo "[pageam] plain read..."
PLAIN=$(
  "$PGBENCH" -n -d "$DBNAME" -c "$CLIENTS" -j "$THREADS" -T "$DURATION" \
    -f "$SCRIPT_DIR/pageam_read_plain.sql" 2>&1 | grep -E "latency average|tps =" || true
)

echo "[pageam] encrypted read..."
ENC=$(
  "$PGBENCH" -n -d "$DBNAME" -c "$CLIENTS" -j "$THREADS" -T "$DURATION" \
    -f "$SCRIPT_DIR/pageam_read_enc.sql" 2>&1 | grep -E "latency average|tps =|ERROR:|FATAL:" || true
)

echo ""
echo "===== PAGEAM 1K READ RESULT ====="
echo "PLAIN:"
echo "$PLAIN"
echo ""
echo "ENCRYPTED (opentde_page):"
echo "$ENC"

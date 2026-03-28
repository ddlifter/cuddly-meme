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

echo "[insert] setup..."
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -f "$SCRIPT_DIR/pgbench_simple_setup.sql"

echo "[insert] plain..."
PLAIN=$( 
  "$PGBENCH" -n -d "$DBNAME" -c "$CLIENTS" -j "$THREADS" -T "$DURATION" \
    -f "$SCRIPT_DIR/pgbench_insert_plain.sql" 2>&1 | grep -E "latency average|tps =" || true
)

echo "[insert] encrypted..."
ENCRYPTED=$( 
  "$PGBENCH" -n -d "$DBNAME" -c "$CLIENTS" -j "$THREADS" -T "$DURATION" \
    -f "$SCRIPT_DIR/pgbench_insert_encrypted.sql" 2>&1 | grep -E "latency average|tps =|ERROR:|FATAL:|Run was aborted" || true
)

echo ""
echo "===== INSERT RESULT ====="
echo "PLAIN:"
echo "$PLAIN"
echo ""
echo "ENCRYPTED:"
echo "$ENCRYPTED"

#!/usr/bin/env bash
source "$(dirname "$0")/vault_env.sh"
set -euo pipefail

DBNAME="${1:-postgres}"
PGBIN="${2:-$HOME/diploma/pg_build/bin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PSQL="$PGBIN/psql"
PGBENCH="$PGBIN/pgbench"

CLIENTS=1
THREADS=1
DURATION=5

echo "[simple] setup..."
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -f "$SCRIPT_DIR/pgbench_simple_setup.sql"

echo "[simple] plain..."

echo "[simple] plain: running pgbench..."
PLAIN_RAW=$("$PGBENCH" -n -d "$DBNAME" -c "$CLIENTS" -j "$THREADS" -T "$DURATION" \
    -f "$SCRIPT_DIR/pgbench_simple_plain.sql" 2>&1 || true)
echo "[simple] plain: raw output:"
echo "$PLAIN_RAW"
PLAIN=$(echo "$PLAIN_RAW" | grep -E "latency average|tps =|ERROR:|FATAL:|Run was aborted" || true)

echo "[simple] encrypted..."

echo "[simple] encrypted: running pgbench..."
ENCRYPTED_RAW=$("$PGBENCH" -n -d "$DBNAME" -c "$CLIENTS" -j "$THREADS" -T "$DURATION" \
    -f "$SCRIPT_DIR/pgbench_simple_encrypted.sql" 2>&1 || true)
echo "[simple] encrypted: raw output:"
echo "$ENCRYPTED_RAW"
ENCRYPTED=$(echo "$ENCRYPTED_RAW" | grep -E "latency average|tps =|ERROR:|FATAL:|Run was aborted" || true)

echo ""
echo "===== SIMPLE RESULT ====="
echo "PLAIN:"
echo "$PLAIN"
echo ""
echo "ENCRYPTED:"
echo "$ENCRYPTED"

#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/vault_env.sh" ]]; then
    # Optional local helper for VAULT_* exports.
    source "$SCRIPT_DIR/vault_env.sh"
fi
set -euo pipefail

DBNAME="postgres"
PGBIN="$HOME/diploma/pg_build/bin"
PGDATA="${PGDATA:-$HOME/pg_data}"

DATA_ROWS="${DATA_ROWS:-10000}"
CLIENTS="${CLIENTS:-1}"
THREADS="${THREADS:-1}"
BENCH_TIME="${BENCH_TIME:-}"
WITH_INDEX=0

# --- Vault environment variables (aligned with e2e_tde_check.sh) ---
export VAULT_ADDR="${VAULT_ADDR:-${OPENTDE_VAULT_ADDR:-http://127.0.0.1:8200}}"
export VAULT_PATH="${VAULT_PATH:-${OPENTDE_VAULT_PATH:-secret/pg_tde}}"
export VAULT_FIELD="${VAULT_FIELD:-${OPENTDE_VAULT_FIELD:-master_key}}"
export VAULT_TOKEN="${VAULT_TOKEN:-${OPENTDE_VAULT_TOKEN:-root}}"
export OPENTDE_VAULT_ADDR="${OPENTDE_VAULT_ADDR:-$VAULT_ADDR}"
export OPENTDE_VAULT_PATH="${OPENTDE_VAULT_PATH:-$VAULT_PATH}"
export OPENTDE_VAULT_FIELD="${OPENTDE_VAULT_FIELD:-$VAULT_FIELD}"
export OPENTDE_VAULT_TOKEN="${OPENTDE_VAULT_TOKEN:-$VAULT_TOKEN}"

if [[ -z "${VAULT_TOKEN:-}" ]]; then
    echo "[simple][WARN] VAULT_TOKEN is not set. Defaulting to local Vault dev token 'root'."
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
    --help|-h)
        echo "Usage: $0 [--db NAME] [--bin PATH] [--rows N] [--clients N] [--jobs N] [-T SEC|--time SEC] [--with-index]"
        echo "Examples:"
        echo "  $0 --rows 1000000 --clients 10 --jobs 10"
        echo "  $0 --rows 1000000 --clients 10 --jobs 10 -T 30"
        echo "  $0 --rows 1000000 --clients 10 --jobs 10 --with-index"
        echo "  $0 --db postgres --bin $HOME/diploma/pg_build/bin --rows 200000"
        exit 0
        ;;
    --rows)
        [[ $# -ge 2 ]] || { echo "--rows requires a value" >&2; exit 1; }
        DATA_ROWS="$2"
        shift 2
        ;;
    --clients)
        [[ $# -ge 2 ]] || { echo "--clients requires a value" >&2; exit 1; }
        CLIENTS="$2"
        shift 2
        ;;
    --jobs|--threads)
        [[ $# -ge 2 ]] || { echo "--jobs requires a value" >&2; exit 1; }
        THREADS="$2"
        shift 2
        ;;
    -T|--time)
        [[ $# -ge 2 ]] || { echo "$1 requires a value" >&2; exit 1; }
        BENCH_TIME="$2"
        shift 2
        ;;
    --with-index)
        WITH_INDEX=1
        shift
        ;;
    --db)
        [[ $# -ge 2 ]] || { echo "--db requires a value" >&2; exit 1; }
        DBNAME="$2"
        shift 2
        ;;
    --bin)
        [[ $# -ge 2 ]] || { echo "--bin requires a value" >&2; exit 1; }
        PGBIN="$2"
        shift 2
        ;;
    *)
        # Backward-compatible positional mode: [dbname] [pgbin]
        if [[ "$DBNAME" == "postgres" ]]; then
            DBNAME="$1"
            shift
        elif [[ "$PGBIN" == "$HOME/diploma/pg_build/bin" ]]; then
            PGBIN="$1"
            shift
        else
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--db NAME] [--bin PATH] [--rows N] [--clients N] [--jobs N] [-T SEC|--time SEC] [--with-index]" >&2
            exit 1
        fi
        ;;
    esac
done

PSQL="$PGBIN/psql"
PGBENCH="$PGBIN/pgbench"

restart_with_preload() {
    local pg_ctl="$PGBIN/pg_ctl"

    "$pg_ctl" -D "$PGDATA" stop -m fast -w >/dev/null 2>&1 || true
    "$pg_ctl" -D "$PGDATA" start -w -o "-c shared_preload_libraries=opentde -c io_method=sync" >/dev/null
}

extract_metrics() {
    local raw="$1"
    echo "$raw" | grep -E "latency average =|tps =" || true
}

run_case() {
    local section="$1"
    local label="$2"
    local script_file="$3"
    local tx_per_client
    local mode_info
    local raw

    # pgbench -t is per client; split total target operations across clients.
    tx_per_client=$(( (DATA_ROWS + CLIENTS - 1) / CLIENTS ))

    if [[ -n "$BENCH_TIME" ]]; then
        mode_info="time=${BENCH_TIME}s"
        echo "[simple] ${section}/${label}: running pgbench (${mode_info})..."
        raw=$("$PGBENCH" -n -d "$DBNAME" -c "$CLIENTS" -j "$THREADS" -T "$BENCH_TIME" -D max_id="$DATA_ROWS" \
            -f "$script_file" 2>&1)
    else
        mode_info="rows=${DATA_ROWS} total"
        echo "[simple] ${section}/${label}: running pgbench (${mode_info})..."
        raw=$("$PGBENCH" -n -d "$DBNAME" -c "$CLIENTS" -j "$THREADS" -t "$tx_per_client" -D max_id="$DATA_ROWS" \
            -f "$script_file" 2>&1)
    fi

    echo "[simple] ${section}/${label}: raw output:"
    echo "$raw"

    echo ""
    echo "${section^^}/${label^^}:"
    extract_metrics "$raw"
}

echo "[simple] config:"
echo "  db=$DBNAME"
echo "  pgbin=$PGBIN"
echo "  rows=$DATA_ROWS"
echo "  clients=$CLIENTS"
echo "  jobs=$THREADS"
echo "  with_index=$WITH_INDEX"
echo "  vault_addr=$VAULT_ADDR"
echo "  vault_path=$VAULT_PATH"
echo "  vault_field=$VAULT_FIELD"
if [[ -n "${VAULT_TOKEN:-}" ]]; then
    echo "  vault_token=<set>"
else
    echo "  vault_token=<empty>"
fi
if [[ -n "$BENCH_TIME" ]]; then
    echo "  mode=time ($BENCH_TIME s)"
else
    echo "  mode=rows (target total $DATA_ROWS)"
fi

echo "[simple] setup..."
restart_with_preload
"$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 -v data_rows="$DATA_ROWS" -v with_index="$WITH_INDEX" -f "$SCRIPT_DIR/pgbench_simple_setup.sql"

echo ""
echo "===== SIMPLE READ RESULT ====="
run_case "read" "plain" "$SCRIPT_DIR/pgbench_simple_plain.sql"
echo ""
run_case "read" "encrypted" "$SCRIPT_DIR/pgbench_simple_encrypted.sql"

echo ""
echo "===== SIMPLE WRITE RESULT ====="
run_case "write" "plain" "$SCRIPT_DIR/pgbench_simple_write_plain.sql"
echo ""
run_case "write" "encrypted" "$SCRIPT_DIR/pgbench_simple_write_encrypted.sql"

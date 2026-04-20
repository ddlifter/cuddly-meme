#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$ROOT_DIR"
RESULT_DIR="$ROOT_DIR/pgbench_results"
mkdir -p "$RESULT_DIR"

DBNAME="${DBNAME:-postgres}"
PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"
PGDATA="${PGDATA:-/tmp/opentde_tps_rows_pgdata}"
PGPORT="${PGPORT:-55452}"

ROWS_LIST_STR="${ROWS_LIST:-5000000 10000000}"
read -r -a ROWS_LIST <<< "$ROWS_LIST_STR"
PROFILE_LIST_STR="${PROFILE_LIST:-4:4:20 16:16:20 32:16:20}"
read -r -a PROFILE_LIST <<< "$PROFILE_LIST_STR"
WORKLOADS=("read" "write")
SKIP_ANALYZE="${SKIP_ANALYZE:-1}"

PSQL="$PGBIN/psql"
PG_CTL="$PGBIN/pg_ctl"
INITDB="$PGBIN/initdb"
PGBENCH="$PGBIN/pgbench"

export VAULT_ADDR="${VAULT_ADDR:-${OPENTDE_VAULT_ADDR:-http://127.0.0.1:8200}}"
export VAULT_PATH="${VAULT_PATH:-${OPENTDE_VAULT_PATH:-secret/pg_tde}}"
export VAULT_FIELD="${VAULT_FIELD:-${OPENTDE_VAULT_FIELD:-master_key}}"
export VAULT_TOKEN="${VAULT_TOKEN:-${OPENTDE_VAULT_TOKEN:-root}}"
export OPENTDE_VAULT_ADDR="${OPENTDE_VAULT_ADDR:-$VAULT_ADDR}"
export OPENTDE_VAULT_PATH="${OPENTDE_VAULT_PATH:-$VAULT_PATH}"
export OPENTDE_VAULT_FIELD="${OPENTDE_VAULT_FIELD:-$VAULT_FIELD}"
export OPENTDE_VAULT_TOKEN="${OPENTDE_VAULT_TOKEN:-$VAULT_TOKEN}"

TS="$(date +%Y%m%d_%H%M%S)"
CSV_OUT="$RESULT_DIR/tps_matrix_rows_${TS}.csv"
MD_OUT="$RESULT_DIR/tps_matrix_rows_${TS}.md"
TMP_SETUP_SQL=""

fail() {
  echo "[TPS-ROWS][ERROR] $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"
}

pg_ready() {
  "$PSQL" -p "$PGPORT" -d "$DBNAME" -Atc "select 1" >/dev/null 2>&1
}

wait_for_ready() {
  local i
  for i in {1..90}; do
    if pg_ready; then
      return 0
    fi
    sleep 1
  done
  fail "PostgreSQL not ready on port $PGPORT"
}

init_cluster() {
  rm -rf "$PGDATA"
  "$INITDB" -D "$PGDATA" >/dev/null
  {
    echo "port = $PGPORT"
    echo "shared_preload_libraries = 'opentde'"
    echo "io_method = 'sync'"
    echo "max_parallel_workers = 0"
    echo "max_parallel_workers_per_gather = 0"
    echo "max_parallel_maintenance_workers = 0"
  } >> "$PGDATA/postgresql.conf"
  "$PG_CTL" -D "$PGDATA" -w -t 600 start >/dev/null
  wait_for_ready
}

cleanup() {
  "$PG_CTL" -D "$PGDATA" -m fast -w -t 120 stop >/dev/null 2>&1 || true
  if [[ -n "$TMP_SETUP_SQL" && -f "$TMP_SETUP_SQL" ]]; then
    rm -f "$TMP_SETUP_SQL"
  fi
}
trap cleanup EXIT

extract_tps() {
  local out="$1"
  local tps
  tps="$(printf '%s\n' "$out" | sed -n 's/^tps = \([0-9.]*\).*/\1/p' | head -n1)"
  if [[ -z "$tps" ]]; then
    echo "NA"
  else
    echo "$tps"
  fi
}

run_case() {
  local workload="$1"
  local variant="$2"
  local clients="$3"
  local jobs="$4"
  local duration="$5"
  local script_file
  local out

  if [[ "$workload" == "read" && "$variant" == "plain" ]]; then
    script_file="$SCRIPT_DIR/pgbench_simple_plain.sql"
  elif [[ "$workload" == "read" && "$variant" == "enc" ]]; then
    script_file="$SCRIPT_DIR/pgbench_simple_encrypted.sql"
  elif [[ "$workload" == "write" && "$variant" == "plain" ]]; then
    script_file="$SCRIPT_DIR/pgbench_simple_write_plain.sql"
  elif [[ "$workload" == "write" && "$variant" == "enc" ]]; then
    script_file="$SCRIPT_DIR/pgbench_simple_write_encrypted.sql"
  else
    fail "Unknown case: $workload/$variant"
  fi

  out="$($PGBENCH -p "$PGPORT" -d "$DBNAME" -n -M simple -c "$clients" -j "$jobs" -T "$duration" --random-seed=1 -D max_id="$ACTIVE_ROWS" -f "$script_file" 2>&1)"
  extract_tps "$out"
}

need_cmd "$PSQL"
need_cmd "$PG_CTL"
need_cmd "$PGBENCH"
need_cmd "$INITDB"

SETUP_SQL="$SCRIPT_DIR/pgbench_simple_setup.sql"
if [[ "$SKIP_ANALYZE" == "1" ]]; then
  TMP_SETUP_SQL="$(mktemp /tmp/pgbench_simple_setup_no_analyze.XXXX.sql)"
  awk '
    BEGIN { in_do = 0 }
    /^DO \$\$/ { in_do = 1; next }
    in_do && /^END \$\$;/ { in_do = 0; next }
    !in_do { print }
  ' "$SETUP_SQL" > "$TMP_SETUP_SQL"
  SETUP_SQL="$TMP_SETUP_SQL"
fi

init_cluster

echo "rows,workload,clients,jobs,duration_s,tps_plain,tps_enc,enc_overhead_pct" > "$CSV_OUT"

echo "# OpenTDE TPS Matrix (Rows)" > "$MD_OUT"
echo "" >> "$MD_OUT"
echo "- Timestamp: $TS" >> "$MD_OUT"
echo "- Port: $PGPORT" >> "$MD_OUT"
echo "- Rows: ${ROWS_LIST[*]}" >> "$MD_OUT"
echo "- Profiles: ${PROFILE_LIST[*]}" >> "$MD_OUT"
echo "" >> "$MD_OUT"
echo "| Rows | Workload | c | j | T(s) | TPS Plain | TPS Enc | Overhead % |" >> "$MD_OUT"
echo "|---:|---|---:|---:|---:|---:|---:|---:|" >> "$MD_OUT"

for rows in "${ROWS_LIST[@]}"; do
  ACTIVE_ROWS="$rows"
  echo "[TPS-ROWS] setup rows=$ACTIVE_ROWS"
  "$PSQL" -p "$PGPORT" -d "$DBNAME" -v ON_ERROR_STOP=1 -v data_rows="$ACTIVE_ROWS" -v with_index=1 -f "$SETUP_SQL" >/tmp/opentde_tps_rows_setup_${ACTIVE_ROWS}.log 2>&1

  for workload in "${WORKLOADS[@]}"; do
    for profile in "${PROFILE_LIST[@]}"; do
      IFS=':' read -r c j t <<< "$profile"
      echo "[TPS-ROWS] rows=$ACTIVE_ROWS workload=$workload c=$c j=$j t=$t"

      tps_plain="$(run_case "$workload" plain "$c" "$j" "$t")"
      tps_enc="$(run_case "$workload" enc "$c" "$j" "$t")"

      if [[ "$tps_plain" == "NA" || "$tps_enc" == "NA" ]]; then
        overhead="NA"
      else
        overhead="$(awk -v p="$tps_plain" -v e="$tps_enc" 'BEGIN { if (p == 0) print "NA"; else printf "%.2f", ((p-e)/p)*100 }')"
      fi

      echo "$ACTIVE_ROWS,$workload,$c,$j,$t,$tps_plain,$tps_enc,$overhead" >> "$CSV_OUT"
      echo "| $ACTIVE_ROWS | $workload | $c | $j | $t | $tps_plain | $tps_enc | $overhead |" >> "$MD_OUT"
    done
  done
done

echo "" >> "$MD_OUT"
echo "CSV: $CSV_OUT" >> "$MD_OUT"
echo "[TPS-ROWS] Done. CSV: $CSV_OUT"
echo "[TPS-ROWS] Done. MD: $MD_OUT"

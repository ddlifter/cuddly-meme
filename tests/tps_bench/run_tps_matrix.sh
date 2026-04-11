#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULT_DIR="$ROOT_DIR/pgbench_results"
mkdir -p "$RESULT_DIR"

DBNAME="${DBNAME:-postgres}"
PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"
PGDATA="${PGDATA:-$HOME/pg_data}"

PSQL="$PGBIN/psql"
PG_CTL="$PGBIN/pg_ctl"
PGBENCH="$PGBIN/pgbench"

export VAULT_ADDR="${VAULT_ADDR:-${OPENTDE_VAULT_ADDR:-http://127.0.0.1:8200}}"
export VAULT_PATH="${VAULT_PATH:-${OPENTDE_VAULT_PATH:-secret/pg_tde}}"
export VAULT_FIELD="${VAULT_FIELD:-${OPENTDE_VAULT_FIELD:-master_key}}"
export VAULT_TOKEN="${VAULT_TOKEN:-${OPENTDE_VAULT_TOKEN:-root}}"
export OPENTDE_VAULT_ADDR="${OPENTDE_VAULT_ADDR:-$VAULT_ADDR}"
export OPENTDE_VAULT_PATH="${OPENTDE_VAULT_PATH:-$VAULT_PATH}"
export OPENTDE_VAULT_FIELD="${OPENTDE_VAULT_FIELD:-$VAULT_FIELD}"
export OPENTDE_VAULT_TOKEN="${OPENTDE_VAULT_TOKEN:-$VAULT_TOKEN}"

MASTER_HEX="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

TS="$(date +%Y%m%d_%H%M%S)"
CSV_OUT="$RESULT_DIR/tps_matrix_$TS.csv"
MD_OUT="$RESULT_DIR/tps_matrix_$TS.md"

TARGET_GB_LIST_STR="${TARGET_GB_LIST:-1 10 30}"
read -r -a TARGET_GB_LIST <<< "$TARGET_GB_LIST_STR"
PROFILE_LIST=("4:4:30" "16:16:30" "32:16:30")
WORKLOADS=("read_point" "read_range" "write_update" "mixed_rw")

fail() {
  echo "[TPS][ERROR] $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"
}

restart_with_tde() {
  "$PG_CTL" -D "$PGDATA" stop -m fast -w -t 600 >/dev/null 2>&1 || true
  "$PG_CTL" -D "$PGDATA" start -w -t 600 -o "-c shared_preload_libraries=opentde -c io_method=sync" >/dev/null
}

wait_for_ready() {
  local i
  for i in {1..60}; do
    if "$PSQL" -d "$DBNAME" -Atc "SELECT 1" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "PostgreSQL is not ready after restart"
}

sql() {
  "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 "$@"
}

sql_val() {
  "$PSQL" -d "$DBNAME" -At -v ON_ERROR_STOP=1 -c "$1"
}

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

human_gb() {
  local bytes="$1"
  awk -v b="$bytes" 'BEGIN { printf "%.2f", b/1024/1024/1024 }'
}

setup_tables_for_target() {
  local target_gb="$1"
  local target_bytes
  local sample_rows=20000
  local bpr
  local rows_needed

  target_bytes="$(awk -v gb="$target_gb" 'BEGIN { printf "%.0f", gb*1024*1024*1024 }')"
  [[ "$target_bytes" =~ ^[0-9]+$ ]] || fail "Invalid target size: $target_gb GB"
  [[ "$target_bytes" -gt 0 ]] || fail "Target size must be > 0: $target_gb GB"

  restart_with_tde
  wait_for_ready

  sql <<SQL
DROP TABLE IF EXISTS tps_size_probe;
DROP FUNCTION IF EXISTS bench_payload(int,bigint);
CREATE OR REPLACE FUNCTION bench_payload(parts int, seed bigint)
RETURNS text
LANGUAGE plpgsql
AS \$\$
DECLARE
  i int;
  out text := '';
BEGIN
  FOR i IN 1..parts LOOP
    out := out || md5(seed::text || ':' || i::text || ':' || random()::text || ':' || clock_timestamp()::text);
  END LOOP;
  RETURN out;
END;
\$\$;

CREATE TABLE tps_size_probe(id bigint, payload text);
INSERT INTO tps_size_probe
SELECT gs, bench_payload(64, gs)
FROM generate_series(1, $sample_rows) gs;
CREATE INDEX tps_size_probe_id_idx ON tps_size_probe(id);
SQL

  bpr="$(sql_val "SELECT (pg_total_relation_size('tps_size_probe') / $sample_rows::numeric)")"
  rows_needed="$(awk -v target="$target_bytes" -v bpr="$bpr" 'BEGIN { r=int(target/bpr); if (r<1) r=1; print r }')"

  echo "[TPS] target=${target_gb}GB, estimated bytes/row=${bpr}, rows=${rows_needed}"

  sql <<SQL
DROP TABLE IF EXISTS tps_size_probe;
DROP TABLE IF EXISTS tps_plain;
DROP TABLE IF EXISTS tps_enc;
DROP EXTENSION IF EXISTS opentde CASCADE;

CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('$MASTER_HEX', 'hex'));

CREATE TABLE tps_plain (
  id bigint,
  payload text
);

CREATE TABLE tps_enc (
  id bigint,
  payload text
);
SELECT opentde_enable_table_encryption('tps_enc'::regclass);

INSERT INTO tps_plain
SELECT gs, bench_payload(64, gs)
FROM generate_series(1, $rows_needed) gs;

INSERT INTO tps_enc
SELECT gs, bench_payload(64, gs)
FROM generate_series(1, $rows_needed) gs;

CREATE INDEX tps_plain_id_idx ON tps_plain(id);
CREATE INDEX tps_enc_id_idx ON tps_enc(id);

ANALYZE tps_plain;
ANALYZE tps_enc;
SQL

  ACTUAL_ROWS="$rows_needed"
  ACTUAL_PLAIN_BYTES="$(sql_val "SELECT pg_total_relation_size('tps_plain')")"
  ACTUAL_ENC_BYTES="$(sql_val "SELECT pg_total_relation_size('tps_enc')")"
}

run_bench() {
  local workload="$1"
  local variant="$2"
  local clients="$3"
  local jobs="$4"
  local duration="$5"
  local script_path="$SCRIPT_DIR/${workload}_${variant}.sql"
  local out

  out="$($PGBENCH -n -d "$DBNAME" -c "$clients" -j "$jobs" -T "$duration" -D max_id="$ACTUAL_ROWS" -f "$script_path" 2>&1)"
  extract_tps "$out"
}

need_cmd "$PSQL"
need_cmd "$PGBENCH"
need_cmd "$PG_CTL"

restart_with_tde
wait_for_ready

echo "target_gb,rows,plain_gb,enc_gb,workload,clients,jobs,duration_s,tps_plain,tps_enc,enc_overhead_pct" > "$CSV_OUT"

echo "# OpenTDE TPS Matrix" > "$MD_OUT"
echo "" >> "$MD_OUT"
echo "- Timestamp: $TS" >> "$MD_OUT"
echo "- DB: $DBNAME" >> "$MD_OUT"
echo "- PGBIN: $PGBIN" >> "$MD_OUT"
echo "- Profiles: ${PROFILE_LIST[*]}" >> "$MD_OUT"
echo "" >> "$MD_OUT"

echo "| Size (GB) | Rows | Plain Size (GB) | Enc Size (GB) | Workload | c | j | T(s) | TPS Plain | TPS Enc | Overhead % |" >> "$MD_OUT"
echo "|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|" >> "$MD_OUT"

for target_gb in "${TARGET_GB_LIST[@]}"; do
  echo "[TPS] Preparing dataset for ${target_gb}GB..."
  setup_tables_for_target "$target_gb"

  plain_gb="$(human_gb "$ACTUAL_PLAIN_BYTES")"
  enc_gb="$(human_gb "$ACTUAL_ENC_BYTES")"

  for wl in "${WORKLOADS[@]}"; do
    for profile in "${PROFILE_LIST[@]}"; do
      IFS=':' read -r c j t <<< "$profile"
      echo "[TPS] size=${target_gb}GB workload=${wl} c=${c} j=${j} T=${t}"

      tps_plain="$(run_bench "$wl" plain "$c" "$j" "$t")"
      tps_enc="$(run_bench "$wl" enc "$c" "$j" "$t")"

      if [[ "$tps_plain" == "NA" || "$tps_enc" == "NA" ]]; then
        overhead="NA"
      else
        overhead="$(awk -v p="$tps_plain" -v e="$tps_enc" 'BEGIN { printf "%.2f", ((p-e)/p)*100 }')"
      fi

      echo "$target_gb,$ACTUAL_ROWS,$plain_gb,$enc_gb,$wl,$c,$j,$t,$tps_plain,$tps_enc,$overhead" >> "$CSV_OUT"
      echo "| $target_gb | $ACTUAL_ROWS | $plain_gb | $enc_gb | $wl | $c | $j | $t | $tps_plain | $tps_enc | $overhead |" >> "$MD_OUT"
    done
  done

done

echo "" >> "$MD_OUT"
echo "CSV: $CSV_OUT" >> "$MD_OUT"
echo "[TPS] Done. CSV: $CSV_OUT"
echo "[TPS] Done. Summary: $MD_OUT"

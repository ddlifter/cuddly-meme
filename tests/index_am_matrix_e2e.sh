#!/usr/bin/env bash
set -euo pipefail

PGDATA="${PGDATA:-$HOME/pg_data}"
DBNAME="${DBNAME:-postgres}"
PGBIN="${PGBIN:-$HOME/diploma/pg_build/bin}"
MASTER_HEX="${MASTER_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

export VAULT_ADDR="${VAULT_ADDR:-${OPENTDE_VAULT_ADDR:-http://127.0.0.1:8200}}"
export VAULT_PATH="${VAULT_PATH:-${OPENTDE_VAULT_PATH:-secret/pg_tde}}"
export VAULT_FIELD="${VAULT_FIELD:-${OPENTDE_VAULT_FIELD:-master_key}}"
export VAULT_TOKEN="${VAULT_TOKEN:-${OPENTDE_VAULT_TOKEN:-root}}"
export OPENTDE_VAULT_ADDR="${OPENTDE_VAULT_ADDR:-$VAULT_ADDR}"
export OPENTDE_VAULT_PATH="${OPENTDE_VAULT_PATH:-$VAULT_PATH}"
export OPENTDE_VAULT_FIELD="${OPENTDE_VAULT_FIELD:-$VAULT_FIELD}"
export OPENTDE_VAULT_TOKEN="${OPENTDE_VAULT_TOKEN:-$VAULT_TOKEN}"

PSQL="$PGBIN/psql"
PG_CTL="$PGBIN/pg_ctl"

fail() {
  echo "[IDX-MATRIX][ERROR] $*" >&2
  exit 1
}

sql() {
  "$PSQL" -d "$DBNAME" -v ON_ERROR_STOP=1 "$@"
}

sql_val() {
  "$PSQL" -d "$DBNAME" -Atc "$1"
}

wait_for_ready() {
  local i
  for i in {1..30}; do
    if "$PSQL" -d "$DBNAME" -c "SELECT 1" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

restart() {
  "$PG_CTL" -D "$PGDATA" stop -m fast -w >/dev/null 2>&1 || true
  "$PG_CTL" -D "$PGDATA" start -w -o "-c shared_preload_libraries=opentde -c io_method=sync" >/dev/null
  wait_for_ready || fail "PostgreSQL is not ready"
}

cleanup_case() {
  local plain_table="$1"
  local enc_table="$2"

  sql <<SQL >/dev/null 2>&1 || true
DROP TABLE IF EXISTS ${plain_table} CASCADE;
DROP TABLE IF EXISTS ${enc_table} CASCADE;
SQL
}

drop_all_cases() {
  sql <<'SQL' >/dev/null 2>&1 || true
DROP TABLE IF EXISTS idx_btree_plain CASCADE;
DROP TABLE IF EXISTS idx_btree_enc CASCADE;
DROP TABLE IF EXISTS idx_hash_plain CASCADE;
DROP TABLE IF EXISTS idx_hash_enc CASCADE;
DROP TABLE IF EXISTS idx_gin_plain CASCADE;
DROP TABLE IF EXISTS idx_gin_enc CASCADE;
DROP TABLE IF EXISTS idx_gist_plain CASCADE;
DROP TABLE IF EXISTS idx_gist_enc CASCADE;
DROP TABLE IF EXISTS idx_spgist_plain CASCADE;
DROP TABLE IF EXISTS idx_spgist_enc CASCADE;
DROP TABLE IF EXISTS idx_brin_plain CASCADE;
DROP TABLE IF EXISTS idx_brin_enc CASCADE;
SQL
}

file_contains_hex() {
  local file_path="$1"
  local hex_pattern="$2"
  hexdump -v -e '/1 "%02x"' "$file_path" | grep -q -i "$hex_pattern"
}

file_contains_text() {
  local file_path="$1"
  local text_value="$2"
  grep -a -q "$text_value" "$file_path"
}

to_hex() {
  printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'
}

reverse_hex32() {
  printf '%s' "$1" | sed -E 's/(..)(..)(..)(..)/\4\3\2\1/'
}

create_case_schema() {
  local case_name="$1"
  local plain_table="idx_${case_name}_plain"
  local enc_table="idx_${case_name}_enc"

  cleanup_case "$plain_table" "$enc_table"

  case "$case_name" in
    btree)
      sql <<SQL
CREATE TABLE ${plain_table} (id int, name text, tags text[], r int4range, payload text);
CREATE TABLE ${enc_table} (id int, name text, tags text[], r int4range, payload text);
SELECT opentde_enable_table_encryption('${enc_table}'::regclass);
CREATE INDEX ${plain_table}_idx ON ${plain_table} USING btree (id);
CREATE INDEX ${enc_table}_idx ON ${enc_table} USING btree (id);
SQL
      ;;
    hash)
      sql <<SQL
CREATE TABLE ${plain_table} (id int, name text, tags text[], r int4range, payload text);
CREATE TABLE ${enc_table} (id int, name text, tags text[], r int4range, payload text);
SELECT opentde_enable_table_encryption('${enc_table}'::regclass);
CREATE INDEX ${plain_table}_idx ON ${plain_table} USING hash (id);
CREATE INDEX ${enc_table}_idx ON ${enc_table} USING hash (id);
SQL
      ;;
    gin)
      sql <<SQL
CREATE TABLE ${plain_table} (id int, name text, tags text[], r int4range, payload text);
CREATE TABLE ${enc_table} (id int, name text, tags text[], r int4range, payload text);
SELECT opentde_enable_table_encryption('${enc_table}'::regclass);
CREATE INDEX ${plain_table}_idx ON ${plain_table} USING gin (tags);
CREATE INDEX ${enc_table}_idx ON ${enc_table} USING gin (tags);
SQL
      ;;
    gist)
      sql <<SQL
CREATE TABLE ${plain_table} (id int, name text, tags text[], r int4range, payload text);
CREATE TABLE ${enc_table} (id int, name text, tags text[], r int4range, payload text);
SELECT opentde_enable_table_encryption('${enc_table}'::regclass);
CREATE INDEX ${plain_table}_idx ON ${plain_table} USING gist (r range_ops);
CREATE INDEX ${enc_table}_idx ON ${enc_table} USING gist (r range_ops);
SQL
      ;;
    spgist)
      sql <<SQL
CREATE TABLE ${plain_table} (id int, name text, tags text[], r int4range, payload text);
CREATE TABLE ${enc_table} (id int, name text, tags text[], r int4range, payload text);
SELECT opentde_enable_table_encryption('${enc_table}'::regclass);
CREATE INDEX ${plain_table}_idx ON ${plain_table} USING spgist (name text_ops);
CREATE INDEX ${enc_table}_idx ON ${enc_table} USING spgist (name text_ops);
SQL
      ;;
    brin)
      sql <<SQL
CREATE TABLE ${plain_table} (id int, name text, tags text[], r int4range, payload text);
CREATE TABLE ${enc_table} (id int, name text, tags text[], r int4range, payload text);
SELECT opentde_enable_table_encryption('${enc_table}'::regclass);
CREATE INDEX ${plain_table}_idx ON ${plain_table} USING brin (id int4_minmax_ops);
CREATE INDEX ${enc_table}_idx ON ${enc_table} USING brin (id int4_minmax_ops);
SQL
      ;;
    *)
      fail "Unknown case: $case_name"
      ;;
  esac
}

insert_rows() {
  local plain_table="$1"
  local enc_table="$2"
  local marker="$3"

  sql <<SQL
INSERT INTO ${plain_table} VALUES
  (1, 'alpha', ARRAY['a','b'], int4range(10, 20), 'row1'),
  (2, 'beta', ARRAY['c','d'], int4range(20, 30), 'row2'),
  (77777, '${marker}', ARRAY['${marker}','z'], int4range(77770, 77780), '${marker}');

INSERT INTO ${enc_table} VALUES
  (1, 'alpha', ARRAY['a','b'], int4range(10, 20), 'row1'),
  (2, 'beta', ARRAY['c','d'], int4range(20, 30), 'row2'),
  (77777, '${marker}', ARRAY['${marker}','z'], int4range(77770, 77780), '${marker}');
SQL
}

verify_full_selects() {
  local plain_table="$1"
  local enc_table="$2"
  local expected_plain="$3"
  local expected_enc="$4"

  [[ "$(sql_val "SELECT count(*)::text FROM ${plain_table};")" == "3" ]] || fail "plain table rowcount mismatch for ${plain_table}"
  [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table};")" == "3" ]] || fail "enc table rowcount mismatch for ${enc_table}"
  [[ "$(sql_val "SELECT string_agg(id::text || ':' || name, ',' ORDER BY id) FROM ${plain_table};")" == "$expected_plain" ]] || fail "plain table full select mismatch for ${plain_table}"
  [[ "$(sql_val "SELECT string_agg(id::text || ':' || name, ',' ORDER BY id) FROM ${enc_table};")" == "$expected_enc" ]] || fail "enc table full select mismatch for ${enc_table}"
}

show_full_rows() {
  local title="$1"
  local table_name="$2"

  echo "[IDX-MATRIX] $title: ${table_name}"
  sql -c "SELECT id, name FROM ${table_name} ORDER BY id;"
}

verify_files() {
  local case_name="$1"
  local plain_idx="$2"
  local enc_idx="$3"
  local marker="$4"

  local plain_relpath
  local enc_relpath
  local plain_file
  local enc_file

  plain_relpath=$(sql_val "SELECT pg_relation_filepath('${plain_idx}'::regclass)")
  enc_relpath=$(sql_val "SELECT pg_relation_filepath('${enc_idx}'::regclass)")
  plain_file="$PGDATA/$plain_relpath"
  enc_file="$PGDATA/$enc_relpath"

  [[ -f "$plain_file" ]] || fail "Missing plain index file: $plain_file"
  [[ -f "$enc_file" ]] || fail "Missing encrypted index file: $enc_file"

  case "$case_name" in
    btree|brin)
      local marker_hex
      marker_hex=$(reverse_hex32 "$(printf '%08x' 77777)")
      file_contains_hex "$plain_file" "$marker_hex" || fail "$case_name plain index does not contain expected int bytes"
      if file_contains_hex "$enc_file" "$marker_hex"; then
        fail "$case_name encrypted index leaked int bytes"
      fi
      ;;
    hash)
      local hash_hex
      local hash_signed
      hash_signed=$(sql_val "SELECT hashint4(77777)")
      hash_hex=$(reverse_hex32 "$(printf '%08x' "$((hash_signed & 0xffffffff))")")
      file_contains_hex "$plain_file" "$hash_hex" || fail "hash plain index does not contain expected hash bytes"
      if file_contains_hex "$enc_file" "$hash_hex"; then
        fail "hash encrypted index leaked hash bytes"
      fi
      ;;
    gin|spgist)
      file_contains_text "$plain_file" "$marker" || fail "$case_name plain index does not contain expected text marker"
      if file_contains_text "$enc_file" "$marker"; then
        fail "$case_name encrypted index leaked text marker"
      fi
      ;;
    gist)
      local marker_hex
      marker_hex=$(reverse_hex32 "$(printf '%08x' 77770)")
      file_contains_hex "$plain_file" "$marker_hex" || fail "gist plain index does not contain expected range bytes"
      if file_contains_hex "$enc_file" "$marker_hex"; then
        fail "gist encrypted index leaked range bytes"
      fi
      ;;
  esac
}

run_case() {
  local case_name="$1"
  local plain_table="idx_${case_name}_plain"
  local enc_table="idx_${case_name}_enc"
  local plain_idx="${plain_table}_idx"
  local enc_idx="${enc_table}_idx"
  local marker="IDX_${case_name}_77777"
  local query
  local expected

  echo "[IDX-MATRIX] Case: $case_name"

  create_case_schema "$case_name"
  insert_rows "$plain_table" "$enc_table" "$marker"
  verify_full_selects "$plain_table" "$enc_table" "1:alpha,2:beta,77777:${marker}" "1:alpha,2:beta,77777:${marker}"
  show_full_rows "Full SELECT before restart (plain)" "$plain_table"
  show_full_rows "Full SELECT before restart (enc)" "$enc_table"
  sql -c "CHECKPOINT;"
  verify_files "$case_name" "$plain_idx" "$enc_idx" "$marker"

  restart

  case "$case_name" in
    btree)
      query="EXPLAIN (COSTS OFF) SELECT name FROM ${enc_table} WHERE id = 77777;"
      expected="$marker"
      [[ "$(sql_val "SELECT name FROM ${enc_table} WHERE id = 77777;")" == "$marker" ]] || fail "btree equality read failed"
      [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table} WHERE id BETWEEN 77770 AND 77780;")" == "1" ]] || fail "btree range read failed"
      ;;
    hash)
      query="EXPLAIN (COSTS OFF) SELECT name FROM ${enc_table} WHERE id = 77777;"
      expected="$marker"
      [[ "$(sql_val "SELECT name FROM ${enc_table} WHERE id = 77777;")" == "$marker" ]] || fail "hash equality read failed"
      sql -c "UPDATE ${enc_table} SET payload = 'updated_${case_name}' WHERE id = 77777;"
      [[ "$(sql_val "SELECT payload FROM ${enc_table} WHERE id = 77777;")" == "updated_${case_name}" ]] || fail "hash update failed"
      ;;
    gin)
      query="EXPLAIN (COSTS OFF) SELECT count(*) FROM ${enc_table} WHERE tags @> ARRAY['${marker}'];"
      expected="$marker"
      [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table} WHERE tags @> ARRAY['${marker}'];")" == "1" ]] || fail "gin containment read failed"
      ;;
    gist)
      query="EXPLAIN (COSTS OFF) SELECT count(*) FROM ${enc_table} WHERE r @> 77775;"
      expected="$marker"
      [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table} WHERE r @> 77775;")" == "1" ]] || fail "gist range read failed"
      sql -c "UPDATE ${enc_table} SET payload = 'updated_${case_name}' WHERE id = 77777;"
      [[ "$(sql_val "SELECT payload FROM ${enc_table} WHERE id = 77777;")" == "updated_${case_name}" ]] || fail "gist update failed"
      ;;
    spgist)
      query="EXPLAIN (COSTS OFF) SELECT count(*) FROM ${enc_table} WHERE name LIKE 'IDX_spgist%';"
      expected="$marker"
      [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table} WHERE name LIKE 'IDX_spgist%';")" == "1" ]] || fail "spgist prefix read failed"
      sql -c "UPDATE ${enc_table} SET payload = 'updated_${case_name}' WHERE id = 77777;"
      [[ "$(sql_val "SELECT payload FROM ${enc_table} WHERE id = 77777;")" == "updated_${case_name}" ]] || fail "spgist update failed"
      ;;
    brin)
      query="EXPLAIN (COSTS OFF) SELECT count(*) FROM ${enc_table} WHERE id BETWEEN 77770 AND 77780;"
      expected="$marker"
      [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table} WHERE id BETWEEN 77770 AND 77780;")" == "1" ]] || fail "brin range read failed"
      sql -c "UPDATE ${enc_table} SET payload = 'updated_${case_name}' WHERE id = 77777;"
      [[ "$(sql_val "SELECT payload FROM ${enc_table} WHERE id = 77777;")" == "updated_${case_name}" ]] || fail "brin update failed"
      ;;
  esac

  plan=$($PSQL -d "$DBNAME" -At \
    -c "SET enable_seqscan=off;" \
    -c "$query" | grep -v '^SET$')
  echo "$plan" | sed 's/^/    /'
  echo "$plan" | grep -Eq "Index Scan|Bitmap Index Scan|Bitmap Heap Scan" || fail "$case_name did not use an index"

  sql -c "INSERT INTO ${enc_table} VALUES (88888, 'new_${case_name}', ARRAY['new_${case_name}'], int4range(88880, 88890), 'new_${case_name}');"
  [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table} WHERE id = 88888;")" == "1" ]] || fail "$case_name insert failed"
  if [[ "$case_name" == "gin" ]]; then
    [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table} WHERE tags @> ARRAY['new_${case_name}'];")" == "1" ]] || fail "gin insert failed"
  fi

  [[ "$(sql_val "SELECT count(*)::text FROM ${plain_table};")" == "3" ]] || fail "$case_name plain table rowcount changed unexpectedly"
  [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table};")" == "4" ]] || fail "$case_name enc table rowcount mismatch after insert"
  [[ "$(sql_val "SELECT string_agg(id::text || ':' || name, ',' ORDER BY id) FROM ${plain_table};")" == "1:alpha,2:beta,77777:${marker}" ]] || fail "$case_name plain table full select changed unexpectedly"

  sql -c "CHECKPOINT;"
  restart

  [[ "$(sql_val "SELECT count(*)::text FROM ${plain_table} WHERE id = 77777;")" == "1" ]] || fail "$case_name plain table read failed after restart"
  [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table} WHERE id = 77777;")" == "1" ]] || fail "$case_name enc table read failed after restart"
  current_payload="$(sql_val "SELECT payload FROM ${enc_table} WHERE id = 77777;")"
  if [[ "$current_payload" != "$expected" && "$current_payload" != "updated_${case_name}" ]]; then
    fail "$case_name payload mismatch after restart"
  fi
  [[ "$(sql_val "SELECT count(*)::text FROM ${plain_table};")" == "3" ]] || fail "$case_name plain rowcount changed after restart"
  [[ "$(sql_val "SELECT string_agg(id::text || ':' || name, ',' ORDER BY id) FROM ${plain_table};")" == "1:alpha,2:beta,77777:${marker}" ]] || fail "$case_name plain full select mismatch after restart"
  [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table};")" == "4" ]] || fail "$case_name enc rowcount mismatch after restart"
  show_full_rows "Full SELECT after restart (plain)" "$plain_table"
  show_full_rows "Full SELECT after restart (enc)" "$enc_table"
  [[ "$(sql_val "SELECT count(*)::text FROM ${enc_table} WHERE id = 88888;")" == "1" ]] || fail "$case_name inserted row missing after restart"

  echo "[IDX-MATRIX] $case_name OK"
}

echo "[IDX-MATRIX] PGDATA=$PGDATA"
echo "[IDX-MATRIX] DBNAME=$DBNAME"

restart
sql <<SQL
DROP EXTENSION IF EXISTS opentde CASCADE;
CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('$MASTER_HEX', 'hex'));
SQL

drop_all_cases
run_case btree
run_case hash
run_case gin
run_case gist
run_case spgist
run_case brin

echo "[IDX-MATRIX] SUCCESS: btree/hash/gin/gist/spgist/brin validated on plain/enc pairs"

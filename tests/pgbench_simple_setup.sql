-- Simple OpenTDE benchmark setup: 10k rows, one int column

\if :{?data_rows}
\else
\set data_rows 10000
\endif

\if :{?with_index}
\else
\set with_index 0
\endif

DROP TABLE IF EXISTS t_simple_encrypted CASCADE;
DROP TABLE IF EXISTS t_simple_plain CASCADE;
DROP TABLE IF EXISTS t_simple_encrypted_write CASCADE;
DROP TABLE IF EXISTS t_simple_plain_write CASCADE;
DROP EXTENSION IF EXISTS opentde CASCADE;

CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex'));


CREATE TABLE t_simple_encrypted (
  id int
)
WITH (
  autovacuum_enabled = false,
  toast.autovacuum_enabled = false
);
SELECT opentde_enable_table_encryption('t_simple_encrypted'::regclass);

CREATE TABLE t_simple_plain (
  id int
)
WITH (
  autovacuum_enabled = false,
  toast.autovacuum_enabled = false
);

CREATE TABLE t_simple_encrypted_write (
  id bigint
)
WITH (
  autovacuum_enabled = false,
  toast.autovacuum_enabled = false
);
SELECT opentde_enable_table_encryption('t_simple_encrypted_write'::regclass);

CREATE TABLE t_simple_plain_write (
  id bigint
)
WITH (
  autovacuum_enabled = false,
  toast.autovacuum_enabled = false
);

\if :with_index
-- For encrypted tables at large scales, building btree on already loaded data
-- can hit unstable scan paths; pre-create the index and maintain it during load.
CREATE INDEX t_simple_encrypted_id_idx ON t_simple_encrypted USING btree(id);
CREATE INDEX t_simple_plain_id_idx ON t_simple_plain USING btree(id);

-- Keep index metadata consistent before bulk load.
REINDEX INDEX t_simple_encrypted_id_idx;
REINDEX INDEX t_simple_plain_id_idx;
\endif

INSERT INTO t_simple_encrypted (id)
SELECT i FROM generate_series(1, :data_rows) AS i;

INSERT INTO t_simple_plain (id)
SELECT i FROM generate_series(1, :data_rows) AS i;

\if :with_index
DO $$
BEGIN
  BEGIN
    EXECUTE 'ANALYZE t_simple_encrypted';
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping ANALYZE for t_simple_encrypted: %', SQLERRM;
  END;

  BEGIN
    EXECUTE 'ANALYZE t_simple_plain';
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Skipping ANALYZE for t_simple_plain: %', SQLERRM;
  END;
END $$;
\endif

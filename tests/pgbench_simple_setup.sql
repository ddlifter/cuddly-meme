-- Simple OpenTDE benchmark setup: 10k rows, one int column

\if :{?data_rows}
\else
\set data_rows 10000
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
);
SELECT opentde_enable_table_encryption('t_simple_encrypted'::regclass);

CREATE TABLE t_simple_plain (
  id int
);

CREATE TABLE t_simple_encrypted_write (
  id bigint
);
SELECT opentde_enable_table_encryption('t_simple_encrypted_write'::regclass);

CREATE TABLE t_simple_plain_write (
  id bigint
);

INSERT INTO t_simple_encrypted (id)
SELECT i FROM generate_series(1, :data_rows) AS i;

INSERT INTO t_simple_plain (id)
SELECT i FROM generate_series(1, :data_rows) AS i;

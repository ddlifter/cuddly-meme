-- Simple OpenTDE benchmark setup: 10k rows, one int column

DROP TABLE IF EXISTS t_simple_encrypted CASCADE;
DROP TABLE IF EXISTS t_simple_plain CASCADE;
DROP EXTENSION IF EXISTS opentde CASCADE;

CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex'));


CREATE TABLE t_simple_encrypted (
  id int
) USING tde;

CREATE TABLE t_simple_plain (
  id int
);

INSERT INTO t_simple_encrypted (id)
SELECT i FROM generate_series(1, 10000) AS i;

INSERT INTO t_simple_plain (id)
SELECT i FROM generate_series(1, 10000) AS i;

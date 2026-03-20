DROP TABLE IF EXISTS t_test CASCADE;
DROP TABLE IF EXISTS t_plain CASCADE;
DROP EXTENSION IF EXISTS opentde CASCADE;
CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex'));

CREATE TABLE t_test (
  id   int,
  name text
) USING opentde;

CREATE TABLE t_plain (
  id   int,
  name text
);

INSERT INTO t_test VALUES (1, 'Привет мир');
INSERT INTO t_test VALUES (2, 'Тестовая строка');
INSERT INTO t_test VALUES (3, 'SENTINEL_OPENTDE_12345');

INSERT INTO t_plain VALUES (1, 'Привет мир');
INSERT INTO t_plain VALUES (2, 'Тестовая строка');
INSERT INTO t_plain VALUES (3, 'SENTINEL_OPENTDE_12345');



UPDATE t_test SET name = 'Обновлённая' WHERE id = 2;

SELECT pg_relation_filepath('t_test'::regclass);
SELECT pg_relation_filepath('t_plain'::regclass);


CREATE INDEX idx_blind ON t_test (opentde_blind_index(name));

SET enable_seqscan=off; EXPLAIN (COSTS OFF) SELECT * FROM t_test WHERE opentde_blind_index(name) = opentde_blind_index('Привет мир');
SET enable_seqscan=off; SELECT name FROM t_test WHERE opentde_blind_index(name) = opentde_blind_index('Привет мир');

SELECT opentde_get_dek_hex('t_test'::regclass::oid);



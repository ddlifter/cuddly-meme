-- PageAM 1k setup: plain vs opentde_page

DROP TABLE IF EXISTS t_page_enc CASCADE;
DROP TABLE IF EXISTS t_page_plain CASCADE;
DROP EXTENSION IF EXISTS opentde CASCADE;

CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex'));

CREATE TABLE t_page_enc (
  id int,
  payload text
) USING opentde_page;

CREATE TABLE t_page_plain (
  id int,
  payload text
);

INSERT INTO t_page_enc(id, payload)
SELECT i, 'secret_pageam_row_' || i::text
FROM generate_series(1, 1000) AS i;

INSERT INTO t_page_plain(id, payload)
SELECT i, 'secret_pageam_row_' || i::text
FROM generate_series(1, 1000) AS i;

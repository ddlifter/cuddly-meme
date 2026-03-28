\set ON_ERROR_STOP on

-- Ensure extension and deterministic master key are present in current DB.
CREATE EXTENSION IF NOT EXISTS opentde;
SELECT opentde_set_master_key(decode(repeat('11', 32), 'hex'));

CREATE OR REPLACE FUNCTION opentde_page_crypto_selftest(oid, int4, bytea)
RETURNS boolean
AS '$libdir/opentde', 'opentde_page_crypto_selftest'
LANGUAGE C STRICT;

-- Build a small payload and verify page-blob roundtrip API.
WITH t AS (
    SELECT 'page-level-smoke-' || repeat('x', 128) AS payload
)
SELECT opentde_page_crypto_selftest('pg_class'::regclass::oid, 42, convert_to(payload, 'UTF8')) AS ok
FROM t;

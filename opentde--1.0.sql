/* opentde--1.0.sql */

\echo Use "CREATE EXTENSION opentde" to load this file. \quit

CREATE FUNCTION opentde_set_master_key(bytea)
RETURNS void
AS 'MODULE_PATHNAME', 'opentde_set_master_key'
LANGUAGE C STRICT;

CREATE FUNCTION opentde_rotate_master_key(bytea)
RETURNS int4
AS 'MODULE_PATHNAME', 'opentde_rotate_master_key'
LANGUAGE C STRICT;

CREATE FUNCTION opentde_rotate_table_dek(oid)
RETURNS int4
AS 'MODULE_PATHNAME', 'opentde_rotate_table_dek_sql'
LANGUAGE C STRICT;

CREATE FUNCTION opentde_pageam_handler(internal)
RETURNS table_am_handler
AS 'MODULE_PATHNAME', 'opentde_pageam_handler'
LANGUAGE C STRICT;

CREATE FUNCTION opentde_debug_keys()
RETURNS text
AS 'MODULE_PATHNAME', 'opentde_debug_keys'
LANGUAGE C STRICT;

CREATE FUNCTION opentde_get_dek_hex(oid)
RETURNS text
AS 'MODULE_PATHNAME', 'opentde_get_dek_hex'
LANGUAGE C STRICT;

CREATE FUNCTION opentde_page_crypto_selftest(oid, int4, bytea)
RETURNS boolean
AS 'MODULE_PATHNAME', 'opentde_page_crypto_selftest'
LANGUAGE C STRICT;


CREATE ACCESS METHOD opentde_page TYPE TABLE HANDLER opentde_pageam_handler;

-- Blind index: HMAC-SHA256(master_key, value).
-- Файл индекса хранит только HMAC-дайджесты, а не открытые значения.
-- Использование:
--   CREATE INDEX ON t ((opentde_blind_index(s)));
--   SELECT * FROM t WHERE opentde_blind_index(s) = opentde_blind_index('искомое');
CREATE FUNCTION opentde_blind_index(text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'opentde_blind_index'
LANGUAGE C IMMUTABLE STRICT;

-- Bucket blind index для диапазонов bigint.
-- В индекс попадает токен бакета, а точность добирается post-filter'ом.
-- Использование:
--   CREATE INDEX idx_amount_bucket
--     ON t ((opentde_blind_bucket_int8(amount, 100)));
--
--   SELECT *
--   FROM t
--   WHERE opentde_blind_bucket_int8(amount, 100)
--         = ANY (opentde_blind_bucket_tokens_int8(1050, 1890, 100))
--     AND amount BETWEEN 1050 AND 1890;
CREATE FUNCTION opentde_blind_bucket_int8(bigint, bigint)
RETURNS bytea
AS 'MODULE_PATHNAME', 'opentde_blind_bucket_int8'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION opentde_blind_bucket_int4(integer, integer)
RETURNS bytea
AS 'MODULE_PATHNAME', 'opentde_blind_bucket_int4'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION opentde_blind_bucket_int8(bigint, integer)
RETURNS bytea
LANGUAGE SQL IMMUTABLE STRICT
AS $$
	SELECT opentde_blind_bucket_int8($1, $2::bigint);
$$;

CREATE FUNCTION opentde_blind_bucket_tokens_int8(bigint, bigint, bigint)
RETURNS bytea[]
AS 'MODULE_PATHNAME', 'opentde_blind_bucket_tokens_int8'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION opentde_blind_bucket_tokens_int8(bigint, bigint, integer)
RETURNS bytea[]
LANGUAGE SQL IMMUTABLE STRICT
AS $$
	SELECT opentde_blind_bucket_tokens_int8($1, $2, $3::bigint);
$$;

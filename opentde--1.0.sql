
-- Включение/выключение column-level encryption
CREATE OR REPLACE FUNCTION set_column_level_encryption(enable boolean)
RETURNS void
AS 'MODULE_PATHNAME', 'set_column_level_encryption'
LANGUAGE C STRICT;
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

CREATE FUNCTION opentde_tableam_handler(internal)
RETURNS table_am_handler
AS 'MODULE_PATHNAME', 'opentde_tableam_handler'
LANGUAGE C STRICT;

CREATE FUNCTION opentde_debug_keys()
RETURNS text
AS 'MODULE_PATHNAME', 'opentde_debug_keys'
LANGUAGE C STRICT;

CREATE FUNCTION opentde_get_dek_hex(oid)
RETURNS text
AS 'MODULE_PATHNAME', 'opentde_get_dek_hex'
LANGUAGE C STRICT;


CREATE ACCESS METHOD opentde TYPE TABLE HANDLER opentde_tableam_handler;

-- Blind index: HMAC-SHA256(master_key, value).
-- Файл индекса хранит только HMAC-дайджесты, а не открытые значения.
-- Использование:
--   CREATE INDEX ON t ((opentde_blind_index(s)));
--   SELECT * FROM t WHERE opentde_blind_index(s) = opentde_blind_index('искомое');
CREATE FUNCTION opentde_blind_index(text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'opentde_blind_index'
LANGUAGE C IMMUTABLE STRICT;

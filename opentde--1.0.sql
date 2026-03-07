/* opentde--1.0.sql */

\echo Use "CREATE EXTENSION opentde" to load this file. \quit

CREATE FUNCTION opentde_set_master_key(bytea)
RETURNS void
AS 'MODULE_PATHNAME', 'opentde_set_master_key'
LANGUAGE C STRICT;

CREATE FUNCTION opentde_tableam_handler(internal)
RETURNS table_am_handler
AS 'MODULE_PATHNAME', 'opentde_tableam_handler'
LANGUAGE C STRICT;

CREATE ACCESS METHOD opentde TYPE TABLE HANDLER opentde_tableam_handler;

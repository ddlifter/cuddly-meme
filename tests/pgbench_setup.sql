-- ============================================================================
-- pgbench Performance Test Setup for OpenTDE
-- ============================================================================
-- Подготовка расширения и таблиц для тестирования производительности

DROP TABLE IF EXISTS t_encrypted CASCADE;
DROP TABLE IF EXISTS t_plain CASCADE;
DROP TABLE IF EXISTS t_encrypted_write CASCADE;
DROP TABLE IF EXISTS t_plain_write CASCADE;
DROP EXTENSION IF EXISTS opentde CASCADE;

CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex'));

-- Таблица с шифрованием (OpenTDE)
CREATE TABLE t_encrypted (
  id   bigint,
  name text,
  balance integer
) USING opentde_page;

-- Обычная таблица (Heap)
CREATE TABLE t_plain (
  id   bigint,
  name text,
  balance integer
);

-- Таблицы для write-теста (INSERT нагрузка)
CREATE TABLE t_encrypted_write (
  id   bigint,
  name text,
  balance integer
) USING opentde_page;

CREATE TABLE t_plain_write (
  id   bigint,
  name text,
  balance integer
);

ALTER TABLE t_encrypted SET (autovacuum_enabled = false);
ALTER TABLE t_plain SET (autovacuum_enabled = false);
ALTER TABLE t_encrypted_write SET (autovacuum_enabled = false);
ALTER TABLE t_plain_write SET (autovacuum_enabled = false);

-- Данные загружаются батчами из pgbench_perf_test.sh.

-- ============================================================================
-- pgbench Performance Test Setup for OpenTDE (with batched inserts)
-- ============================================================================
-- Подготовка расширения и таблиц для тестирования производительности

DROP TABLE IF EXISTS t_encrypted CASCADE;
DROP TABLE IF EXISTS t_plain CASCADE;
DROP EXTENSION IF EXISTS opentde CASCADE;

CREATE EXTENSION opentde;
SELECT opentde_set_master_key(decode('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex'));

-- Таблица с шифрованием (OpenTDE)

CREATE TABLE t_encrypted (
  id   bigint PRIMARY KEY,
  name text,
  balance integer,
  email text,
  data text
) USING tde;

-- Обычная таблица (Heap)
CREATE TABLE t_plain (
  id   bigint PRIMARY KEY,
  name text,
  balance integer,
  email text,
  data text
);

-- Индексы для обеих таблиц
CREATE INDEX idx_encrypted_name ON t_encrypted(name);
CREATE INDEX idx_plain_name ON t_plain(name);

-- Заполнение таблиц батчами по 500 строк (2 батча = 1000 строк)
INSERT INTO t_encrypted (id, name, balance, email, data)
SELECT
  generate_series(1, 500) AS id,
  'user_' || generate_series(1, 500) AS name,
  (random() * 10000)::integer AS balance,
  'user_' || generate_series(1, 500) || '@example.com' AS email,
  repeat('Test data block with some random content ', 10) AS data;

INSERT INTO t_encrypted (id, name, balance, email, data)
SELECT
  generate_series(501, 1000) AS id,
  'user_' || generate_series(501, 1000) AS name,
  (random() * 10000)::integer AS balance,
  'user_' || generate_series(501, 1000) || '@example.com' AS email,
  repeat('Test data block with some random content ', 10) AS data;

-- Копируем в обычную таблицу
INSERT INTO t_plain (id, name, balance, email, data)
SELECT * FROM t_encrypted;

-- Индексы готовы, автовакуум подготовит статистику
ANALYZE t_encrypted;
ANALYZE t_plain;

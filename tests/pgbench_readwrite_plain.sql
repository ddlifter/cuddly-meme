-- ============================================================================
-- pgbench Read-Write Test (Mixed)
-- ============================================================================
-- Смешанная нагрузка для обычной таблицы
\set id random(1, 1000)
SELECT id, name, balance FROM t_plain WHERE id = :id;
SELECT id, name, balance FROM t_plain WHERE id = :id + 1;
SELECT id, name, balance FROM t_plain WHERE id = :id + 2;
UPDATE t_plain SET balance = balance + 1 WHERE id = :id;

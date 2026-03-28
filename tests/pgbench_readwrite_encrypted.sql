-- ============================================================================
-- pgbench Read-Write Test (Mixed)
-- ============================================================================
-- Смешанная нагрузка: более частые SELECT, реже UPDATE
\set id random(1, 1000)
SELECT id, name, balance FROM t_encrypted WHERE id = :id;
SELECT id, name, balance FROM t_encrypted WHERE id = :id + 1;
SELECT id, name, balance FROM t_encrypted WHERE id = :id + 2;
UPDATE t_encrypted SET balance = balance + 1 WHERE id = :id;

-- ============================================================================
-- pgbench Write Test
-- ============================================================================
-- Простые INSERT запросы для зашифрованной таблицы
\set bid random(1, 1000000000)
INSERT INTO t_encrypted_write (id, name, balance)
SELECT 900000000000 + :bid, 'new_safe_' || :bid::text, 1
WHERE NOT EXISTS (
	SELECT 1 FROM t_encrypted_write WHERE id = 900000000000 + :bid
);

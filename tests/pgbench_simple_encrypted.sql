-- Simple encrypted table read test
\set id random(1, :max_id)
SELECT id FROM t_simple_encrypted WHERE id = :id;

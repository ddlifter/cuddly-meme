-- Simple plain table read test
\set id random(1, :max_id)
SELECT id FROM t_simple_plain WHERE id = :id;

-- Simple plain table read test
\set id random(1, 10000)
SELECT id FROM t_simple_plain WHERE id = :id;

-- Simple encrypted table read test
\set id random(1, 10000)
SELECT id FROM t_simple_encrypted WHERE id = :id;

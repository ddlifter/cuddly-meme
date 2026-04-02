-- Simple plain table write-only test
\set id random(1, 1000000000)
INSERT INTO t_simple_plain_write(id) VALUES (:id);

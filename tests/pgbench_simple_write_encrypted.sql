-- Simple encrypted table write-only test
\set id random(1, 1000000000)
INSERT INTO t_simple_encrypted_write(id) VALUES (:id);

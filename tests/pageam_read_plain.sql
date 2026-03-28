\set id random(1, 1000)
SELECT id, payload FROM t_page_plain WHERE id = :id;

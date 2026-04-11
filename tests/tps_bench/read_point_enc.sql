\set id random(1, :max_id)
SELECT payload FROM tps_enc WHERE id = :id;

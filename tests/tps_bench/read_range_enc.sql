\set id random(1, :max_id)
SELECT count(*) FROM tps_enc WHERE id BETWEEN :id AND (:id + 100);

\set id random(1, :max_id)
SELECT payload FROM tps_plain WHERE id = :id;
SELECT count(*) FROM tps_plain WHERE id BETWEEN :id AND (:id + 30);
UPDATE tps_plain
SET payload = substr(payload, 1, 1900) || md5(clock_timestamp()::text)
WHERE id = :id;

\set id random(1, :max_id)
UPDATE tps_enc
SET payload = substr(payload, 1, 1900) || md5(clock_timestamp()::text)
WHERE id = :id;

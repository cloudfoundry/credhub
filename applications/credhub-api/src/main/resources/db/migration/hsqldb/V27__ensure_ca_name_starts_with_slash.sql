UPDATE
  certificate_secret
SET
  ca_name = CONCAT('/', ca_name)
WHERE
  ca_name IS NOT NULL AND ca_name NOT LIKE '/%';

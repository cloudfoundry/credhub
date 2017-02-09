UPDATE
  named_certificate_authority
SET
  name = CONCAT('/', name)
WHERE
  name NOT LIKE '/%';


UPDATE
  certificate_secret
SET
  ca_name = CONCAT('/', ca_name)
WHERE
  ca_name IS NOT NULL AND ca_name NOT LIKE '/%';


UPDATE
  certificate_secret
SET
  ca_name = CONCAT(ca_name, '-ca')
WHERE
  EXISTS(
    SELECT 1
    FROM named_certificate_authority, named_secret
    WHERE certificate_secret.ca_name = named_certificate_authority.name
      AND certificate_secret.ca_name = named_secret.name
  );


UPDATE
  named_certificate_authority
SET
  name = CONCAT(named_certificate_authority.name, '-ca')
WHERE
  EXISTS(
    SELECT name
    FROM named_secret
    WHERE named_secret.name = named_certificate_authority.name
  );


INSERT INTO
  named_secret
  (uuid, name, type, encrypted_value, nonce, updated_at, version_created_at, encryption_key_uuid)
SELECT
  uuid, name, 'cert', encrypted_value, nonce, updated_at, version_created_at, encryption_key_uuid
FROM
  named_certificate_authority;


INSERT INTO
  certificate_secret
  (uuid, ca, certificate, ca_name)
SELECT
  uuid, NULL, certificate, name
FROM
  named_certificate_authority;
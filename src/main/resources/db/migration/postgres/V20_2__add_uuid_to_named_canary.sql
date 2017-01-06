ALTER TABLE encryption_key_canary ALTER COLUMN uuid SET NOT NULL;
ALTER TABLE encryption_key_canary DROP CONSTRAINT named_canary_pkey;
ALTER TABLE encryption_key_canary ADD CONSTRAINT encryption_key_canary_pkey PRIMARY KEY (uuid);
ALTER TABLE encryption_key_canary DROP COLUMN id;

ALTER TABLE named_certificate_authority ADD COLUMN encryption_key_uuid UUID;
ALTER TABLE named_secret ADD COLUMN encryption_key_uuid UUID;
ALTER TABLE password_secret ADD COLUMN parameter_encryption_key_uuid UUID;

UPDATE named_certificate_authority
  SET encryption_key_uuid = existing_canary.uuid
  FROM (
    SELECT uuid
    FROM encryption_key_canary
    WHERE name = 'canary'
    LIMIT 1
  ) AS existing_canary;

UPDATE named_secret
  SET encryption_key_uuid = existing_canary.uuid
  FROM (
    SELECT uuid
    FROM encryption_key_canary
    WHERE name = 'canary'
    LIMIT 1
  ) AS existing_canary;

UPDATE password_secret
  SET parameter_encryption_key_uuid = existing_canary.uuid
  FROM (
    SELECT uuid
    FROM encryption_key_canary
    WHERE name = 'canary'
    LIMIT 1
  ) AS existing_canary;

ALTER TABLE encryption_key_canary DROP COLUMN name;

ALTER TABLE named_certificate_authority ALTER COLUMN encryption_key_uuid SET NOT NULL;
ALTER TABLE named_secret ALTER COLUMN encryption_key_uuid SET NOT NULL;
ALTER TABLE password_secret ALTER COLUMN parameter_encryption_key_uuid SET NOT NULL;

ALTER TABLE named_certificate_authority
  ADD CONSTRAINT named_certificate_authority_encryption_key_uuid_fkey
  FOREIGN KEY(encryption_key_uuid) REFERENCES encryption_key_canary(uuid);
ALTER TABLE named_secret
  ADD CONSTRAINT named_secret_encryption_key_uuid_fkey
  FOREIGN KEY(encryption_key_uuid) REFERENCES encryption_key_canary(uuid);
ALTER TABLE password_secret
  ADD CONSTRAINT password_secret_parameter_encryption_key_uuid_fkey
  FOREIGN KEY(parameter_encryption_key_uuid) REFERENCES encryption_key_canary(uuid);

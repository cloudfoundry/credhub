ALTER TABLE encryption_key_canary MODIFY COLUMN uuid BINARY(16) NOT NULL;
ALTER TABLE encryption_key_canary MODIFY id BIGINT(20) NOT NULL;
ALTER TABLE encryption_key_canary DROP PRIMARY KEY;
ALTER TABLE encryption_key_canary ADD PRIMARY KEY (uuid);
ALTER TABLE encryption_key_canary DROP COLUMN id;

ALTER TABLE named_certificate_authority ADD COLUMN encryption_key_uuid BINARY(16);
ALTER TABLE named_secret ADD COLUMN encryption_key_uuid BINARY(16);
ALTER TABLE password_secret ADD COLUMN parameter_encryption_key_uuid BINARY(16);

UPDATE named_certificate_authority
  SET encryption_key_uuid = (
    SELECT uuid
    FROM encryption_key_canary
    WHERE encryption_key_canary.name = 'canary'
    LIMIT 1
  );

UPDATE named_secret
  SET encryption_key_uuid = (
    SELECT uuid
    FROM encryption_key_canary
    WHERE encryption_key_canary.name = 'canary'
    LIMIT 1
  );

UPDATE password_secret
  SET parameter_encryption_key_uuid = (
    SELECT uuid
    FROM encryption_key_canary
    WHERE encryption_key_canary.name = 'canary'
    LIMIT 1
  );

ALTER TABLE encryption_key_canary DROP COLUMN name;

ALTER TABLE named_certificate_authority MODIFY COLUMN encryption_key_uuid BINARY(16) NOT NULL;
ALTER TABLE named_secret MODIFY COLUMN encryption_key_uuid BINARY(16) NOT NULL;
ALTER TABLE password_secret MODIFY COLUMN parameter_encryption_key_uuid BINARY(16) NOT NULL;

ALTER TABLE named_certificate_authority
  ADD CONSTRAINT named_certificate_authority_encryption_key_uuid_fkey
  FOREIGN KEY(encryption_key_uuid) REFERENCES encryption_key_canary(uuid);
ALTER TABLE named_secret
  ADD CONSTRAINT named_secret_encryption_key_uuid_fkey
  FOREIGN KEY(encryption_key_uuid) REFERENCES encryption_key_canary(uuid);
ALTER TABLE password_secret
  ADD CONSTRAINT password_secret_parameter_encryption_key_uuid_fkey
  FOREIGN KEY(parameter_encryption_key_uuid) REFERENCES encryption_key_canary(uuid);

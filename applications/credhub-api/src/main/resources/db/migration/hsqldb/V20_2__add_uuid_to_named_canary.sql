ALTER TABLE encryption_key_canary ALTER COLUMN uuid BINARY(16) NOT NULL;
ALTER TABLE encryption_key_canary ADD PRIMARY KEY (uuid);
ALTER TABLE encryption_key_canary DROP COLUMN id;
ALTER TABLE encryption_key_canary DROP COLUMN name;

ALTER TABLE named_certificate_authority ADD COLUMN encryption_key_uuid BINARY(16);
ALTER TABLE named_secret ADD COLUMN encryption_key_uuid BINARY(16);
ALTER TABLE password_secret ADD COLUMN parameter_encryption_key_uuid BINARY(16);

UPDATE named_certificate_authority
  SET named_certificate_authority.encryption_key_uuid = (
    SELECT encryption_key_canary.uuid
    FROM encryption_key_canary
    LIMIT 1
  );

UPDATE named_secret
  SET named_secret.encryption_key_uuid = (
    SELECT encryption_key_canary.uuid
    FROM encryption_key_canary
    LIMIT 1
  );

UPDATE password_secret
  SET password_secret.parameter_encryption_key_uuid = (
    SELECT encryption_key_canary.uuid
    FROM encryption_key_canary
    LIMIT 1
  );

ALTER TABLE named_certificate_authority ALTER COLUMN encryption_key_uuid BINARY(16) NOT NULL;
ALTER TABLE named_secret ALTER COLUMN encryption_key_uuid BINARY(16) NOT NULL;
ALTER TABLE password_secret ALTER COLUMN parameter_encryption_key_uuid BINARY(16) NOT NULL;

ALTER TABLE named_certificate_authority
  ADD CONSTRAINT named_certificate_authority_encryption_key_uuid_fkey FOREIGN KEY(encryption_key_uuid)
  REFERENCES encryption_key_canary(uuid);
ALTER TABLE named_secret
  ADD CONSTRAINT named_secret_encryption_key_uuid_fkey FOREIGN KEY(encryption_key_uuid)
  REFERENCES encryption_key_canary(uuid);
ALTER TABLE password_secret
  ADD CONSTRAINT password_secret_parameter_encryption_key_uuid_fkey FOREIGN KEY(parameter_encryption_key_uuid)
  REFERENCES encryption_key_canary(uuid);

ALTER TABLE password_secret
  DROP CONSTRAINT password_secret_parameter_encryption_key_uuid_fkey;

ALTER TABLE password_secret
  DROP COLUMN parameter_encryption_key_uuid;

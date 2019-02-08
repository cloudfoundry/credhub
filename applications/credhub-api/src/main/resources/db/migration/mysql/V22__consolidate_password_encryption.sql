ALTER TABLE password_secret
  DROP FOREIGN KEY password_secret_parameter_encryption_key_uuid_fkey;

ALTER TABLE password_secret
  DROP COLUMN parameter_encryption_key_uuid;

ALTER TABLE credential_version
  DROP CONSTRAINT named_secret_encryption_key_uuid_fkey;

ALTER TABLE credential_version
  DROP COLUMN encryption_key_uuid;

ALTER TABLE credential_version
  DROP COLUMN encrypted_value;

ALTER TABLE credential_version
  DROP COLUMN nonce;

ALTER TABLE credential_version
  DROP COLUMN updated_at;

ALTER TABLE password_credential
  DROP COLUMN encrypted_generation_parameters;

ALTER TABLE password_credential
  DROP COLUMN parameters_nonce;

ALTER TABLE user_credential
  DROP COLUMN encrypted_generation_parameters;

ALTER TABLE user_credential
  DROP COLUMN parameters_nonce;

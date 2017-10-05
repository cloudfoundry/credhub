ALTER TABLE credential_version
  ADD COLUMN encrypted_value_uuid BINARY(16);

ALTER TABLE password_credential
  ADD COLUMN password_parameters_uuid BINARY(16);

ALTER TABLE user_credential
  ADD COLUMN password_parameters_uuid BINARY(16);

ALTER TABLE credential_version
  ADD CONSTRAINT credential_encrypted_value_uuid_fkey
  FOREIGN KEY(encrypted_value_uuid)
  REFERENCES encrypted_value(uuid);

ALTER TABLE password_credential
  ADD CONSTRAINT password_parameters_uuid_fkey
  FOREIGN KEY(password_parameters_uuid)
  REFERENCES encrypted_value(uuid);

ALTER TABLE user_credential
  ADD CONSTRAINT user_password_parameters_uuid_fkey
  FOREIGN KEY(password_parameters_uuid)
  REFERENCES encrypted_value(uuid);


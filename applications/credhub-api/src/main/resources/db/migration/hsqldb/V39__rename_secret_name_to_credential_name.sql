ALTER TABLE secret_name
  RENAME TO credential_name;

ALTER TABLE named_secret
  ALTER COLUMN secret_name_uuid
  RENAME TO credential_name_uuid;

ALTER TABLE access_entry
  ALTER COLUMN secret_name_uuid
  RENAME TO credential_name_uuid;

ALTER TABLE named_secret
  DROP CONSTRAINT secret_name_uuid_fkey;

ALTER TABLE named_secret
  ADD CONSTRAINT credential_name_uuid_fkey
  FOREIGN KEY(credential_name_uuid)
  REFERENCES credential_name(uuid)
  ON DELETE CASCADE;

ALTER TABLE access_entry
  DROP CONSTRAINT secret_name_uuid_access_fkey;

ALTER TABLE access_entry
  ADD CONSTRAINT credential_name_uuid_access_fkey
  FOREIGN KEY(credential_name_uuid)
  REFERENCES credential_name(uuid)
  ON DELETE CASCADE;

ALTER TABLE secret_name
  RENAME TO credential_name;

ALTER TABLE named_secret
  DROP FOREIGN KEY secret_name_uuid_fkey;

ALTER TABLE named_secret
  CHANGE COLUMN secret_name_uuid credential_name_uuid VARBINARY(16) NOT NULL;

ALTER TABLE named_secret
  ADD CONSTRAINT credential_name_uuid_fkey
  FOREIGN KEY(credential_name_uuid)
  REFERENCES credential_name(uuid)
  ON DELETE CASCADE;

ALTER TABLE access_entry
  DROP FOREIGN KEY secret_name_uuid_access_fkey;

ALTER TABLE access_entry
  CHANGE COLUMN secret_name_uuid credential_name_uuid VARBINARY(16) NOT NULL;

ALTER TABLE access_entry
  ADD CONSTRAINT credential_name_uuid_access_fkey
  FOREIGN KEY(credential_name_uuid)
  REFERENCES credential_name(uuid)
  ON DELETE CASCADE;

ALTER TABLE credential_version
  DROP FOREIGN KEY credential_name_uuid_fkey;

ALTER TABLE credential_version
  CHANGE COLUMN credential_name_uuid credential_uuid VARBINARY(16) NOT NULL;

ALTER TABLE credential_version
  ADD CONSTRAINT credential_uuid_fkey
  FOREIGN KEY(credential_uuid)
  REFERENCES credential(uuid)
  ON DELETE CASCADE;


ALTER TABLE access_entry
  DROP FOREIGN KEY credential_name_uuid_access_fkey;

ALTER TABLE access_entry
  CHANGE COLUMN credential_name_uuid credential_uuid VARBINARY(16) NOT NULL;

ALTER TABLE access_entry
  ADD CONSTRAINT credential_uuid_access_fkey
  FOREIGN KEY(credential_uuid)
  REFERENCES credential(uuid)
  ON DELETE CASCADE;

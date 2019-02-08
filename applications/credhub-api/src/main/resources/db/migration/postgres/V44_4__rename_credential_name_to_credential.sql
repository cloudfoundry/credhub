ALTER TABLE credential_version
  RENAME COLUMN credential_name_uuid
  TO credential_uuid;

ALTER TABLE credential_version
  RENAME CONSTRAINT credential_name_uuid_fkey
  TO credential_uuid_fkey;

ALTER TABLE access_entry
  RENAME COLUMN credential_name_uuid
  TO credential_uuid;

ALTER TABLE access_entry
  RENAME CONSTRAINT credential_name_uuid_access_fkey
  TO credential_uuid_access_fkey;

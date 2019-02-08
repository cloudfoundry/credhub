ALTER TABLE secret_name
  RENAME TO credential_name;

ALTER TABLE named_secret
  RENAME COLUMN secret_name_uuid
  TO credential_name_uuid;

ALTER TABLE named_secret
  RENAME CONSTRAINT secret_name_uuid_fkey
  TO credential_name_uuid_fkey;

ALTER TABLE access_entry
  RENAME COLUMN secret_name_uuid
  TO credential_name_uuid;

ALTER TABLE access_entry
  RENAME CONSTRAINT secret_name_uuid_access_fkey
  TO credential_name_uuid_access_fkey;

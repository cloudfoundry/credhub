CREATE CACHED TABLE access_entry (
  uuid BINARY(16) NOT NULL,
  secret_name_uuid BINARY(16) NOT NULL,
  actor VARCHAR_IGNORECASE(255) NOT NULL,
  read_permission BOOL DEFAULT FALSE NOT NULL,
  write_permission BOOL DEFAULT FALSE NOT NULL
);

ALTER TABLE access_entry
  ADD CONSTRAINT access_entry_pkey PRIMARY KEY(uuid);

ALTER TABLE access_entry
  ADD CONSTRAINT actor_resource_unique UNIQUE(actor, secret_name_uuid);

ALTER TABLE access_entry
  ADD CONSTRAINT secret_name_uuid_access_fkey
  FOREIGN KEY(secret_name_uuid)
  REFERENCES secret_name(uuid)
  ON DELETE CASCADE;

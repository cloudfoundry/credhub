CREATE TABLE access_entry (
  uuid uuid NOT NULL,
  secret_name_uuid uuid NOT NULL,
  actor CHARACTER VARYING(255) NOT NULL,
  read_permission BOOL DEFAULT FALSE,
  write_permission BOOL DEFAULT FALSE
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

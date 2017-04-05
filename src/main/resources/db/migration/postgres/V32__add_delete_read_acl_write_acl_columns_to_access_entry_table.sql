ALTER TABLE access_entry
  ADD COLUMN delete_permission BOOL DEFAULT FALSE NOT NULL;

ALTER TABLE access_entry
  ADD COLUMN read_acl_permission BOOL DEFAULT FALSE NOT NULL;

ALTER TABLE access_entry
  ADD COLUMN write_acl_permission BOOL DEFAULT FALSE NOT NULL;

ALTER TABLE access_entry
  ADD CONSTRAINT read_permission_not_null_constraint NOT NULL(read_permission);

ALTER TABLE access_entry
  ADD CONSTRAINT write_permission_not_null_constraint NOT NULL(write_permission);

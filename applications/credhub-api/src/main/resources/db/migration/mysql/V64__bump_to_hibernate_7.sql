-- Fix for schema-validation errors:
-- wrong column type encountered in column [credential_uuid] in table [credential_version];
-- found [varbinary (Types#VARBINARY)], but expecting [binary(16) (Types#BINARY)]
-- Hibernate 7 (Spring Boot 4) maps Java UUID to BINARY(16) for MySQL instead of VARBINARY.
-- FOREIGN_KEY_CHECKS=0 on ADD CONSTRAINT skips the referential integrity validation scan,
-- which is safe because the data was already under a FK constraint before this migration.
ALTER TABLE credential_version DROP FOREIGN KEY credential_uuid_fkey;
ALTER TABLE credential_version MODIFY COLUMN credential_uuid BINARY(16) NOT NULL;
SET FOREIGN_KEY_CHECKS=0;
ALTER TABLE credential_version
  ADD CONSTRAINT credential_uuid_fkey
  FOREIGN KEY (credential_uuid)
  REFERENCES credential(uuid)
  ON DELETE CASCADE;
SET FOREIGN_KEY_CHECKS=1;

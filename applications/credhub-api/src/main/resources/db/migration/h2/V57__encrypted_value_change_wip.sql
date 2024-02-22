ALTER TABLE encrypted_value ADD COLUMN credential_version_uuid BINARY(16);

ALTER TABLE encrypted_value ADD CONSTRAINT credential_version_uuid_fkey FOREIGN KEY(credential_version_uuid) REFERENCES credential_version(uuid) ON DELETE CASCADE;

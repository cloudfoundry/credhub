START TRANSACTION;

ALTER TABLE password_secret DROP CONSTRAINT IF EXISTS password_secret_uuid_fkey;
ALTER TABLE password_secret ADD CONSTRAINT password_secret_uuid_fkey FOREIGN KEY(uuid) REFERENCES named_secret(uuid) ON DELETE CASCADE;

ALTER TABLE value_secret DROP CONSTRAINT IF EXISTS value_secret_uuid_fkey;
ALTER TABLE value_secret ADD CONSTRAINT value_secret_uuid_fkey FOREIGN KEY(uuid) REFERENCES named_secret(uuid) ON DELETE CASCADE;

ALTER TABLE certificate_secret DROP CONSTRAINT IF EXISTS certificate_secret_uuid_fkey;
ALTER TABLE certificate_secret ADD CONSTRAINT certificate_secret_uuid_fkey FOREIGN KEY(uuid) REFERENCES named_secret(uuid) ON DELETE CASCADE;

ALTER TABLE ssh_secret DROP CONSTRAINT IF EXISTS ssh_secret_uuid_fkey;
ALTER TABLE ssh_secret ADD CONSTRAINT ssh_secret_uuid_fkey FOREIGN KEY(uuid) REFERENCES named_secret(uuid) ON DELETE CASCADE;

ALTER TABLE rsa_secret DROP CONSTRAINT IF EXISTS rsa_secret_uuid_fkey;
ALTER TABLE rsa_secret ADD CONSTRAINT rsa_secret_uuid_fkey FOREIGN KEY(uuid) REFERENCES named_secret(uuid) ON DELETE CASCADE;

COMMIT;

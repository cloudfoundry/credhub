START TRANSACTION;

ALTER TABLE password_secret DROP FOREIGN KEY password_secret_ibfk_1;
ALTER TABLE password_secret ADD CONSTRAINT password_secret_uuid_fkey FOREIGN KEY(uuid) REFERENCES named_secret(uuid) ON DELETE CASCADE;

ALTER TABLE value_secret DROP FOREIGN KEY value_secret_ibfk_1;
ALTER TABLE value_secret ADD CONSTRAINT value_secret_uuid_fkey FOREIGN KEY(uuid) REFERENCES named_secret(uuid) ON DELETE CASCADE;

ALTER TABLE certificate_secret DROP FOREIGN KEY certificate_secret_ibfk_1;
ALTER TABLE certificate_secret ADD CONSTRAINT certificate_secret_uuid_fkey FOREIGN KEY(uuid) REFERENCES named_secret(uuid) ON DELETE CASCADE;

ALTER TABLE ssh_secret DROP FOREIGN KEY ssh_secret_ibfk_1;
ALTER TABLE ssh_secret ADD CONSTRAINT ssh_secret_uuid_fkey FOREIGN KEY(uuid) REFERENCES named_secret(uuid) ON DELETE CASCADE;

ALTER TABLE rsa_secret DROP FOREIGN KEY rsa_secret_ibfk_1;
ALTER TABLE rsa_secret ADD CONSTRAINT rsa_secret_uuid_fkey FOREIGN KEY(uuid) REFERENCES named_secret(uuid) ON DELETE CASCADE;

COMMIT;

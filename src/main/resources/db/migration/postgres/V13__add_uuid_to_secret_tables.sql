ALTER TABLE named_secret ADD CONSTRAINT named_secret_unique_uuid UNIQUE (uuid);

ALTER TABLE value_secret ADD COLUMN uuid uuid;
ALTER TABLE password_secret ADD COLUMN uuid uuid;
ALTER TABLE certificate_secret ADD COLUMN uuid uuid;
ALTER TABLE ssh_secret ADD COLUMN uuid uuid;
ALTER TABLE rsa_secret ADD COLUMN uuid uuid;

UPDATE value_secret
  SET uuid = named_secret.uuid
  FROM named_secret
  WHERE value_secret.id = named_secret.id;
UPDATE password_secret
  SET uuid = named_secret.uuid
  FROM named_secret
  WHERE password_secret.id = named_secret.id;
UPDATE certificate_secret
  SET uuid = named_secret.uuid
  FROM named_secret
  WHERE certificate_secret.id = named_secret.id;
UPDATE ssh_secret
  SET uuid = named_secret.uuid
  FROM named_secret
  WHERE ssh_secret.id = named_secret.id;
UPDATE rsa_secret
  SET uuid = named_secret.uuid
  FROM named_secret
  WHERE rsa_secret.id = named_secret.id;

ALTER TABLE value_secret ALTER COLUMN uuid SET NOT NULL;
ALTER TABLE password_secret ALTER COLUMN uuid SET NOT NULL;
ALTER TABLE certificate_secret ALTER COLUMN uuid SET NOT NULL;
ALTER TABLE ssh_secret ALTER COLUMN uuid SET NOT NULL;
ALTER TABLE rsa_secret ALTER COLUMN uuid SET NOT NULL;

ALTER TABLE value_secret ADD FOREIGN KEY(uuid) REFERENCES named_secret(uuid);
ALTER TABLE password_secret ADD FOREIGN KEY(uuid) REFERENCES named_secret(uuid);
ALTER TABLE certificate_secret ADD FOREIGN KEY(uuid) REFERENCES named_secret(uuid);
ALTER TABLE ssh_secret ADD FOREIGN KEY(uuid) REFERENCES named_secret(uuid);
ALTER TABLE rsa_secret ADD FOREIGN KEY(uuid) REFERENCES named_secret(uuid);

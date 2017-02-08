ALTER TABLE named_secret
  ADD COLUMN secret_name_uuid VARBINARY(16);

UPDATE named_secret
  SET named_secret.secret_name_uuid = (
    SELECT uuid
      FROM secret_name
      WHERE secret_name.name = named_secret.name
  );

ALTER TABLE named_secret
  ALTER COLUMN secret_name_uuid VARBINARY(16) NOT NULL;

ALTER TABLE named_secret
  ADD CONSTRAINT secret_name_uuid_fkey
  FOREIGN KEY(secret_name_uuid)
  REFERENCES secret_name(uuid)
  ON DELETE CASCADE;

ALTER TABLE named_secret
  DROP COLUMN name;

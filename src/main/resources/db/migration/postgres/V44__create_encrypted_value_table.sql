CREATE TABLE encrypted_value (
  uuid uuid NOT NULL PRIMARY KEY,
  encryption_key_uuid uuid NOT NULL,
  encrypted_value bytea NOT NULL,
  nonce bytea NOT NULL,
  updated_at bigint NOT NULL
);

ALTER TABLE encrypted_value
  ADD CONSTRAINT encryption_key_uuid_fkey
  FOREIGN KEY(encryption_key_uuid)
  REFERENCES encryption_key_canary(uuid);


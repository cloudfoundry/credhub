CREATE TABLE encrypted_value (
  uuid BINARY(16) NOT NULL PRIMARY KEY,
  encryption_key_uuid BINARY(16) NOT NULL,
  encrypted_value BLOB NOT NULL,
  nonce TINYBLOB NOT NULL,
  updated_at BIGINT(20) NOT NULL
);

ALTER TABLE encrypted_value
  ADD CONSTRAINT encryption_key_uuid_fkey
  FOREIGN KEY(encryption_key_uuid)
  REFERENCES encryption_key_canary(uuid);


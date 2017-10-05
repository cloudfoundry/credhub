CREATE CACHED TABLE encrypted_value (
  uuid BINARY(16) NOT NULL PRIMARY KEY,
  encryption_key_uuid BINARY(16) NOT NULL,
  encrypted_value BINARY(7016) NOT NULL,
  nonce BINARY(16) NOT NULL,
  updated_at BIGINT NOT NULL,
);

ALTER TABLE encrypted_value
  ADD CONSTRAINT encryption_key_uuid_fkey
  FOREIGN KEY(encryption_key_uuid)
  REFERENCES encryption_key_canary(uuid);

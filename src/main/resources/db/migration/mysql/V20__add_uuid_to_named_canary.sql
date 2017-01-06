RENAME TABLE named_canary TO encryption_key_canary;
ALTER TABLE encryption_key_canary ADD COLUMN uuid BINARY(16);

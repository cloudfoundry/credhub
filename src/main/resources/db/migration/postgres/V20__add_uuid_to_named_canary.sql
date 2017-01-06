ALTER TABLE named_canary RENAME TO encryption_key_canary;

ALTER TABLE encryption_key_canary ADD COLUMN uuid UUID;

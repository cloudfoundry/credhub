ALTER TABLE named_secret ALTER COLUMN uuid TYPE uuid USING uuid::uuid;
ALTER TABLE named_secret ALTER COLUMN uuid SET NOT NULL;

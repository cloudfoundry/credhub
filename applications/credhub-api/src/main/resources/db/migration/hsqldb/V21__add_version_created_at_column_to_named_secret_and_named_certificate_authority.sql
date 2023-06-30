ALTER TABLE named_secret ADD COLUMN version_created_at BIGINT;

UPDATE named_secret
  SET version_created_at = updated_at;

ALTER TABLE named_secret ALTER COLUMN version_created_at SET NOT NULL;



ALTER TABLE named_certificate_authority ADD COLUMN version_created_at BIGINT;

UPDATE named_certificate_authority
  SET version_created_at = updated_at;

ALTER TABLE named_certificate_authority ALTER COLUMN version_created_at SET NOT NULL;

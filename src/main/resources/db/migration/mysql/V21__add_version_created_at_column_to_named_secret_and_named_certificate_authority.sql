ALTER TABLE named_secret ADD COLUMN version_created_at BIGINT(20);

UPDATE named_secret
  SET version_created_at = updated_at;

ALTER TABLE named_secret MODIFY COLUMN version_created_at BIGINT(20) NOT NULL;



ALTER TABLE named_certificate_authority ADD COLUMN version_created_at BIGINT(20);

UPDATE named_certificate_authority
  SET version_created_at = updated_at;

ALTER TABLE named_certificate_authority MODIFY COLUMN version_created_at BIGINT(20) NOT NULL;


ALTER TABLE credential ALTER COLUMN checksum VARCHAR(100) NOT NULL;
ALTER TABLE credential DROP CONSTRAINT name_unique;

ALTER TABLE credential
  ALTER COLUMN name VARCHAR(1024) DEFAULT NOT NULL;

ALTER TABLE certificate_credential
  ALTER COLUMN ca_name VARCHAR(1024);

ALTER TABLE event_audit_record
  ALTER COLUMN credential_name VARCHAR(1024);

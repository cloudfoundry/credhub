ALTER TABLE credential
  MODIFY COLUMN name VARCHAR(255) NOT NULL;

ALTER TABLE certificate_credential
  MODIFY COLUMN ca_name VARCHAR(255);

ALTER TABLE event_audit_record
  MODIFY COLUMN credential_name VARCHAR(255);

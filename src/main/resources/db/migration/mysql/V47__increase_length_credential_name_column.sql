ALTER TABLE credential
  MODIFY COLUMN name VARCHAR(1024) NOT NULL;

ALTER TABLE certificate_credential
  MODIFY COLUMN ca_name VARCHAR(1024);

ALTER TABLE event_audit_record
  MODIFY COLUMN credential_name VARCHAR(1024);

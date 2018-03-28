ALTER TABLE credential
  MODIFY COLUMN name VARCHAR(767) NOT NULL;

ALTER TABLE certificate_credential
  MODIFY COLUMN ca_name VARCHAR(767);

ALTER TABLE event_audit_record
  MODIFY COLUMN credential_name VARCHAR(767);


ALTER TABLE credential ALTER checksum SET NOT NULL;

ALTER TABLE credential DROP CONSTRAINT name_unique;

ALTER TABLE credential ALTER COLUMN name TYPE VARCHAR(1024);

ALTER TABLE certificate_credential ALTER COLUMN ca_name TYPE VARCHAR(1024);

ALTER TABLE event_audit_record ALTER COLUMN credential_name TYPE VARCHAR(1024);

CREATE TABLE credential_new LIKE credential;

ALTER TABLE credential_new ADD name_sha1 CHAR(40);

ALTER TABLE credential_new ADD UNIQUE KEY (name_sha1);

INSERT INTO credential_new (uuid,name,name_sha1)
  SELECT uuid,name,SHA1(name) FROM credential;

DROP INDEX name_unique ON credential_new;

ALTER TABLE credential RENAME credential_old;

ALTER TABLE credential_new RENAME credential;

--DROP TABLE credential_old;

ALTER TABLE credential
  MODIFY COLUMN name VARCHAR(1024) NOT NULL;

ALTER TABLE certificate_credential
  MODIFY COLUMN ca_name VARCHAR(1024);

ALTER TABLE event_audit_record
  MODIFY COLUMN credential_name VARCHAR(1024);

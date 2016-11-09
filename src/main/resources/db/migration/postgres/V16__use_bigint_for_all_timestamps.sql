ALTER TABLE auth_failure_audit_record ADD COLUMN temp_now bigint;

UPDATE auth_failure_audit_record
  SET temp_now = cast(extract(epoch from now) as bigint);

ALTER TABLE auth_failure_audit_record DROP COLUMN now;

ALTER TABLE auth_failure_audit_record RENAME temp_now TO now;
ALTER TABLE auth_failure_audit_record ALTER COLUMN now SET NOT NULL;

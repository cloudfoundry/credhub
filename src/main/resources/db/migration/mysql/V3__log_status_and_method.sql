ALTER TABLE operation_audit_record
  ADD method VARCHAR(255) DEFAULT NULL,
  ADD status_code INT;

ALTER TABLE auth_failure_audit_record
  ADD method VARCHAR(255) DEFAULT NULL,
  ADD status_code INT;

ALTER TABLE operation_audit_record
  ADD query_parameters VARCHAR(255) DEFAULT NULL;

ALTER TABLE auth_failure_audit_record
  ADD query_parameters VARCHAR(255) DEFAULT NULL;

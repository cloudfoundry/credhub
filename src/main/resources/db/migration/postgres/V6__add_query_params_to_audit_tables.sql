ALTER TABLE operation_audit_record
  ADD query_parameters character varying(255);

ALTER TABLE auth_failure_audit_record
  ADD query_parameters character varying(255);

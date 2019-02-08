ALTER TABLE operation_audit_record
  ADD method character varying(255),
  ADD status_code int;

ALTER TABLE auth_failure_audit_record
  ADD method character varying(255),
  ADD status_code int;

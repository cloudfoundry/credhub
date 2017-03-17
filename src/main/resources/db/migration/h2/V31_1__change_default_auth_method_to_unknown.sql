ALTER TABLE operation_audit_record
    DROP CONSTRAINT op_audit_auth_method_constraint;

ALTER TABLE operation_audit_record
  ADD CONSTRAINT op_audit_auth_method_constraint CHECK (auth_method IN ('unknown', 'uaa', 'mutual_tls'));

ALTER TABLE operation_audit_record
  ALTER COLUMN auth_method
  VARCHAR(10)
  DEFAULT 'unknown' NOT NULL;

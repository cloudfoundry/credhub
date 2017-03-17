ALTER TABLE operation_audit_record
  ALTER COLUMN token_expires
  RENAME TO auth_valid_until;

ALTER TABLE operation_audit_record
  ALTER COLUMN token_issued
  RENAME TO auth_valid_from;

ALTER TABLE operation_audit_record
  ADD auth_method
  VARCHAR(10) DEFAULT 'uaa' NOT NULL;

ALTER TABLE operation_audit_record
  ADD CONSTRAINT op_audit_auth_method_constraint CHECK (auth_method IN ('uaa', 'mutual_tls'));



ALTER TABLE auth_failure_audit_record
  ALTER COLUMN token_expires
  RENAME TO auth_valid_until;

ALTER TABLE auth_failure_audit_record
  ALTER COLUMN token_issued
  RENAME TO auth_valid_from;

ALTER TABLE auth_failure_audit_record
  ADD auth_method
  VARCHAR(10) DEFAULT 'uaa' NOT NULL;

ALTER TABLE auth_failure_audit_record
  ADD CONSTRAINT failure_audit_auth_method_constraint CHECK (auth_method IN ('uaa', 'mutual_tls'));
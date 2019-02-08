ALTER TABLE operation_audit_record
  RENAME COLUMN token_expires
  TO auth_valid_until;

ALTER TABLE operation_audit_record
  RENAME COLUMN token_issued
  TO auth_valid_from;

ALTER TABLE operation_audit_record
  ADD auth_method character varying(10)
  DEFAULT 'uaa' NOT NULL;

ALTER TABLE operation_audit_record
  ADD CONSTRAINT op_audit_auth_method_constraint CHECK (auth_method IN ('uaa', 'mutual_tls'));



ALTER TABLE auth_failure_audit_record
  RENAME COLUMN token_expires
  TO auth_valid_until;

ALTER TABLE auth_failure_audit_record
  RENAME COLUMN token_issued
  TO auth_valid_from;

ALTER TABLE auth_failure_audit_record
  ADD auth_method character varying(10)
  DEFAULT 'uaa' NOT NULL;

ALTER TABLE auth_failure_audit_record
  ADD CONSTRAINT failure_audit_auth_method_constraint CHECK (auth_method IN ('uaa', 'mutual_tls'));
ALTER TABLE request_audit_record
  DROP CONSTRAINT request_audit_method_auth_method_constraint;

ALTER TABLE request_audit_record
  ADD CONSTRAINT request_audit_method_auth_method_constraint
  CHECK (auth_method IN ('uaa', 'mutual_tls', 'unknown'));

ALTER TABLE `request_audit_record`
  MODIFY `auth_method`
  VARCHAR(10) DEFAULT 'unknown' NOT NULL;

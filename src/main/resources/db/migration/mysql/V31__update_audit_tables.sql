ALTER TABLE `operation_audit_record`
  CHANGE `token_expires` `auth_valid_until` bigint(20) NOT NULL;

ALTER TABLE `operation_audit_record`
  CHANGE `token_issued` `auth_valid_from` bigint(20) NOT NULL;

ALTER TABLE `operation_audit_record`
  ADD `auth_method`
  VARCHAR(10) DEFAULT 'uaa' NOT NULL;

ALTER TABLE `operation_audit_record`
  ADD CONSTRAINT `op_audit_auth_method_constraint` CHECK (auth_method IN ('uaa', 'mutual_tls'));



ALTER TABLE `auth_failure_audit_record`
  CHANGE `token_expires` `auth_valid_until` bigint(20) NOT NULL;

ALTER TABLE `auth_failure_audit_record`
  CHANGE `token_issued` `auth_valid_from` bigint(20) NOT NULL;

ALTER TABLE `auth_failure_audit_record`
  ADD `auth_method`
  VARCHAR(10) DEFAULT 'uaa' NOT NULL;

ALTER TABLE `auth_failure_audit_record`
  ADD CONSTRAINT `failure_audit_auth_method_constraint` CHECK (auth_method IN ('uaa', 'mutual_tls'));
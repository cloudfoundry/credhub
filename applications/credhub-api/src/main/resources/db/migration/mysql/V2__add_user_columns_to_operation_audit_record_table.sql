ALTER TABLE operation_audit_record
    ADD scope VARCHAR(255) DEFAULT NULL,
    ADD grant_type VARCHAR(255) DEFAULT NULL,
    ADD client_id VARCHAR(255) DEFAULT NULL;

ALTER TABLE auth_failure_audit_record
    ADD scope VARCHAR(255) DEFAULT NULL,
    ADD grant_type VARCHAR(255) DEFAULT NULL,
    ADD client_id VARCHAR(255) DEFAULT NULL;

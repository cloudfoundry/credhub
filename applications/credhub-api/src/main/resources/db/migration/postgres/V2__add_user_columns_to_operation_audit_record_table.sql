ALTER TABLE operation_audit_record
    ADD scope character varying(255),
    ADD grant_type character varying(255),
    ADD client_id character varying(255);

ALTER TABLE auth_failure_audit_record
    ADD scope character varying(255),
    ADD grant_type character varying(255),
    ADD client_id character varying(255);

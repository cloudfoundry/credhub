ALTER TABLE event_audit_record
  ADD COLUMN ace_actor character varying(255);

ALTER TABLE event_audit_record
  ADD COLUMN ace_operation character varying(255);

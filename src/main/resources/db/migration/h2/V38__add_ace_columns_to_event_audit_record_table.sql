ALTER TABLE event_audit_record
  ADD COLUMN ace_actor VARCHAR(255);

ALTER TABLE event_audit_record
  ADD COLUMN ace_operation VARCHAR(255);

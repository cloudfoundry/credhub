CREATE TABLE request_audit_record (
  uuid BINARY(16) NOT NULL,
  host_name VARCHAR(255),
  now BIGINT NOT NULL,
  path VARCHAR(255),
  requester_ip VARCHAR(255),
  auth_valid_from BIGINT NOT NULL,
  auth_valid_until BIGINT NOT NULL,
  uaa_url VARCHAR(255),
  user_id VARCHAR(255),
  user_name VARCHAR(255),
  x_forwarded_for VARCHAR(255),
  scope VARCHAR(255),
  grant_type VARCHAR(255),
  client_id VARCHAR(255),
  method VARCHAR(255),
  status_code INT,
  query_parameters VARCHAR(255),
  auth_method VARCHAR(10) DEFAULT 'uaa' NOT NULL
);

ALTER TABLE request_audit_record
  ADD CONSTRAINT request_audit_record_pkey
  PRIMARY KEY(uuid);

ALTER TABLE request_audit_record
  ADD CONSTRAINT request_audit_method_auth_method_constraint
  CHECK (auth_method IN ('uaa', 'mutual_tls'));

CREATE TABLE event_audit_record (
  uuid BINARY(16) NOT NULL,
  request_uuid BINARY(16) NOT NULL,
  now BIGINT NOT NULL,
  operation VARCHAR(255),
  credential_name VARCHAR(255),
  actor VARCHAR(255),
  success BOOLEAN NOT NULL
);

ALTER TABLE event_audit_record
  ADD CONSTRAINT event_audit_record_pkey
  PRIMARY KEY(uuid);

ALTER TABLE event_audit_record
  ADD CONSTRAINT event_audit_record_request_uuid_fkey
  FOREIGN KEY(request_uuid)
  REFERENCES request_audit_record(uuid);

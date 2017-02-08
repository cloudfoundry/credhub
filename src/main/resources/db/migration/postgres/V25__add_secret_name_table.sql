CREATE TABLE secret_name (
  uuid uuid NOT NULL,
  name CHARACTER VARYING(255) NOT NULL
);

ALTER TABLE secret_name
  ADD CONSTRAINT secret_name_pkey PRIMARY KEY(uuid);

ALTER TABLE secret_name
  ADD CONSTRAINT name_unique UNIQUE(name);

CREATE UNIQUE INDEX secret_name_unique ON secret_name(lower(name));

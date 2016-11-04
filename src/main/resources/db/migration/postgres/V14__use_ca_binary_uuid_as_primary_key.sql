ALTER TABLE named_certificate_authority ALTER COLUMN uuid TYPE uuid USING uuid::uuid;
ALTER TABLE named_certificate_authority ALTER COLUMN uuid SET NOT NULL;

ALTER TABLE named_certificate_authority DROP CONSTRAINT named_certificate_authority_pkey;

ALTER TABLE named_certificate_authority ADD CONSTRAINT named_certificate_authority_pkey PRIMARY KEY(uuid);

ALTER TABLE named_certificate_authority DROP COLUMN IF EXISTS id;

ALTER TABLE value_secret DROP CONSTRAINT fkox93sy15f6pgbdr89kp05pnfq;
ALTER TABLE password_secret DROP CONSTRAINT fk31hqe03pkugu8u5ng564ko2nv;
ALTER TABLE certificate_secret DROP CONSTRAINT fk34brqrqsrtkaf3gmty1rjkyjd;
ALTER TABLE ssh_secret DROP CONSTRAINT ssh_secret_fkey;
ALTER TABLE rsa_secret DROP CONSTRAINT rsa_secret_fkey;

ALTER TABLE value_secret DROP CONSTRAINT value_secret_pkey;
ALTER TABLE password_secret DROP CONSTRAINT password_secret_pkey;
ALTER TABLE certificate_secret DROP CONSTRAINT certificate_secret_pkey;
ALTER TABLE ssh_secret DROP CONSTRAINT ssh_secret_pkey;
ALTER TABLE rsa_secret DROP CONSTRAINT rsa_secret_pkey;

ALTER TABLE value_secret ADD CONSTRAINT value_secret_pkey PRIMARY KEY(uuid);
ALTER TABLE password_secret ADD CONSTRAINT password_secret_pkey PRIMARY KEY(uuid);
ALTER TABLE certificate_secret ADD CONSTRAINT certificate_secret_pkey PRIMARY KEY(uuid);
ALTER TABLE ssh_secret ADD CONSTRAINT ssh_secret_pkey PRIMARY KEY(uuid);
ALTER TABLE rsa_secret ADD CONSTRAINT rsa_secret_pkey PRIMARY KEY(uuid);

ALTER TABLE value_secret DROP COLUMN IF EXISTS id;
ALTER TABLE password_secret DROP COLUMN IF EXISTS id;
ALTER TABLE certificate_secret DROP COLUMN IF EXISTS id;
ALTER TABLE ssh_secret DROP COLUMN IF EXISTS id;
ALTER TABLE rsa_secret DROP COLUMN IF EXISTS id;

ALTER TABLE named_secret DROP CONSTRAINT named_secret_pkey;

ALTER TABLE named_secret ADD CONSTRAINT named_secret_pkey PRIMARY KEY(uuid);

ALTER TABLE named_secret DROP COLUMN IF EXISTS id;

ALTER TABLE VALUE_SECRET ADD COLUMN UUID BINARY(16);
ALTER TABLE PASSWORD_SECRET ADD COLUMN UUID BINARY(16);
ALTER TABLE CERTIFICATE_SECRET ADD COLUMN UUID BINARY(16);
ALTER TABLE SSH_SECRET ADD COLUMN UUID BINARY(16);
ALTER TABLE RSA_SECRET ADD COLUMN UUID BINARY(16);

UPDATE value_secret
  SET value_secret.uuid = (
    SELECT named_secret.uuid
    FROM named_secret
    WHERE value_secret.id = named_secret.id
  );
UPDATE password_secret
  SET password_secret.uuid = (
    SELECT named_secret.uuid
    FROM named_secret
    WHERE password_secret.id = named_secret.id
  );
UPDATE certificate_secret
  SET certificate_secret.uuid = (
    SELECT named_secret.uuid
    FROM named_secret
    WHERE certificate_secret.id = named_secret.id
  );
UPDATE ssh_secret
  SET ssh_secret.uuid = (
    SELECT named_secret.uuid
    FROM named_secret
    WHERE ssh_secret.id = named_secret.id
  );
UPDATE rsa_secret
  SET rsa_secret.uuid = (
    SELECT named_secret.uuid
    FROM named_secret
    WHERE rsa_secret.id = named_secret.id
  );

ALTER TABLE VALUE_SECRET ALTER COLUMN UUID BINARY(16) NOT NULL;
ALTER TABLE PASSWORD_SECRET ALTER COLUMN UUID BINARY(16) NOT NULL;
ALTER TABLE CERTIFICATE_SECRET ALTER COLUMN UUID BINARY(16) NOT NULL;
ALTER TABLE SSH_SECRET ALTER COLUMN UUID BINARY(16) NOT NULL;
ALTER TABLE RSA_SECRET ALTER COLUMN UUID BINARY(16) NOT NULL;

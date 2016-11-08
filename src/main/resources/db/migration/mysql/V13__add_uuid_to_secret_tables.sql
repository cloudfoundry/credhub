ALTER TABLE `named_secret` ADD CONSTRAINT named_secret_unique_uuid UNIQUE (`uuid`);

ALTER TABLE `value_secret` ADD COLUMN `uuid` binary(16);
ALTER TABLE `password_secret` ADD COLUMN `uuid` binary(16);
ALTER TABLE `certificate_secret` ADD COLUMN `uuid` binary(16);
ALTER TABLE `ssh_secret` ADD COLUMN `uuid` binary(16);
ALTER TABLE `rsa_secret` ADD COLUMN `uuid` binary(16);

UPDATE value_secret
  INNER JOIN named_secret ON value_secret.id = named_secret.id
  SET value_secret.uuid = named_secret.uuid;
UPDATE password_secret
  INNER JOIN named_secret ON password_secret.id = named_secret.id
  SET password_secret.uuid = named_secret.uuid;
UPDATE certificate_secret
  INNER JOIN named_secret ON certificate_secret.id = named_secret.id
  SET certificate_secret.uuid = named_secret.uuid;
UPDATE ssh_secret
  INNER JOIN named_secret ON ssh_secret.id = named_secret.id
  SET ssh_secret.uuid = named_secret.uuid;
UPDATE rsa_secret
  INNER JOIN named_secret ON rsa_secret.id = named_secret.id
  SET rsa_secret.uuid = named_secret.uuid;

ALTER TABLE `value_secret` MODIFY COLUMN `uuid` binary(16) NOT NULL;
ALTER TABLE `password_secret` MODIFY COLUMN `uuid` binary(16) NOT NULL;
ALTER TABLE `certificate_secret` MODIFY COLUMN `uuid` binary(16) NOT NULL;
ALTER TABLE `ssh_secret` MODIFY COLUMN `uuid` binary(16) NOT NULL;
ALTER TABLE `rsa_secret` MODIFY COLUMN `uuid` binary(16) NOT NULL;

ALTER TABLE `value_secret` ADD FOREIGN KEY (`uuid`) REFERENCES `named_secret` (`uuid`);
ALTER TABLE `password_secret` ADD FOREIGN KEY (`uuid`) REFERENCES `named_secret` (`uuid`);
ALTER TABLE `certificate_secret` ADD FOREIGN KEY (`uuid`) REFERENCES `named_secret` (`uuid`);
ALTER TABLE `ssh_secret` ADD FOREIGN KEY (`uuid`) REFERENCES `named_secret` (`uuid`);
ALTER TABLE `rsa_secret` ADD FOREIGN KEY (`uuid`) REFERENCES `named_secret` (`uuid`);

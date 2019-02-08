ALTER TABLE `named_secret` ADD COLUMN `temp_uuid` binary(16) NOT NULL;
UPDATE `named_secret` SET `temp_uuid` = unhex(replace(`uuid`, '-', ''));
ALTER TABLE `named_secret` DROP COLUMN `uuid`;
ALTER TABLE `named_secret` CHANGE COLUMN `temp_uuid` `uuid` binary(16) NOT NULL;

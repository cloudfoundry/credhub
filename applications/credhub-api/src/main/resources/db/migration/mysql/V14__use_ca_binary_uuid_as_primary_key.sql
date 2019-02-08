ALTER TABLE `named_certificate_authority` ADD COLUMN `temp_uuid` binary(16) NOT NULL;
UPDATE `named_certificate_authority` SET `temp_uuid` = unhex(replace(`uuid`, '-', ''));
ALTER TABLE `named_certificate_authority` DROP COLUMN `uuid`;
ALTER TABLE `named_certificate_authority` CHANGE COLUMN `temp_uuid` `uuid` binary(16) NOT NULL;

-- mysql requires the auto_increment constraint to be dropped before the primary key constraint
ALTER TABLE `named_certificate_authority` MODIFY id bigint(20) NOT NULL;
ALTER TABLE `named_certificate_authority` DROP PRIMARY KEY;

ALTER TABLE `named_certificate_authority` ADD PRIMARY KEY(`uuid`);

ALTER TABLE `named_certificate_authority` DROP COLUMN `id`;

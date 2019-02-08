ALTER TABLE `auth_failure_audit_record` ADD COLUMN `temp_now` BIGINT(20);

UPDATE `auth_failure_audit_record`
  SET `temp_now` = UNIX_TIMESTAMP(CONVERT_TZ(`now`, '+00:00', @@session.time_zone));

ALTER TABLE `auth_failure_audit_record` DROP COLUMN `now`;

ALTER TABLE `auth_failure_audit_record` CHANGE COLUMN `temp_now` `now` BIGINT(20) NOT NULL;

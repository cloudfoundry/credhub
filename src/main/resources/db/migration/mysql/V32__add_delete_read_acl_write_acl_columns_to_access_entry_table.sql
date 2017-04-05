ALTER TABLE `access_entry`
  ADD COLUMN `delete_permission` BOOLEAN NOT NULL DEFAULT 0;

ALTER TABLE `access_entry`
  ADD COLUMN `read_acl_permission` BOOLEAN NOT NULL DEFAULT 0;

ALTER TABLE `access_entry`
  ADD COLUMN `write_acl_permission` BOOLEAN NOT NULL DEFAULT 0;

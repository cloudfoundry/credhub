ALTER TABLE `value_secret` DROP FOREIGN KEY FKox93sy15f6pgbdr89kp05pnfq;
ALTER TABLE `password_secret` DROP FOREIGN KEY FK31hqe03pkugu8u5ng564ko2nv;
ALTER TABLE `certificate_secret` DROP FOREIGN KEY FK34brqrqsrtkaf3gmty1rjkyjd;
ALTER TABLE `ssh_secret` DROP FOREIGN KEY ssh_secret_fkey;
ALTER TABLE `rsa_secret` DROP FOREIGN KEY rsa_secret_fkey;

ALTER TABLE `value_secret` DROP PRIMARY KEY;
ALTER TABLE `password_secret` DROP PRIMARY KEY;
ALTER TABLE `certificate_secret` DROP PRIMARY KEY;
ALTER TABLE `ssh_secret` DROP PRIMARY KEY;
ALTER TABLE `rsa_secret` DROP PRIMARY KEY;

ALTER TABLE `value_secret` ADD PRIMARY KEY (`uuid`);
ALTER TABLE `password_secret` ADD PRIMARY KEY (`uuid`);
ALTER TABLE `certificate_secret` ADD PRIMARY KEY (`uuid`);
ALTER TABLE `ssh_secret` ADD PRIMARY KEY (`uuid`);
ALTER TABLE `rsa_secret` ADD PRIMARY KEY (`uuid`);

ALTER TABLE `value_secret` DROP COLUMN `id`;
ALTER TABLE `password_secret` DROP COLUMN `id`;
ALTER TABLE `certificate_secret` DROP COLUMN `id`;
ALTER TABLE `ssh_secret` DROP COLUMN `id`;
ALTER TABLE `rsa_secret` DROP COLUMN `id`;

-- mysql requires the auto_increment constraint to be dropped before the primary key constraint
ALTER TABLE `named_secret` MODIFY id bigint(20) NOT NULL;
ALTER TABLE `named_secret` DROP PRIMARY KEY;

ALTER TABLE `named_secret` ADD PRIMARY KEY(`uuid`);

ALTER TABLE `named_secret` DROP COLUMN `id`;

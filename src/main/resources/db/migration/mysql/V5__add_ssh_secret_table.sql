CREATE TABLE `certificate_secret` (
  `public_key` varchar(7000) DEFAULT NULL,
  `id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `ssh_secret_fkey` FOREIGN KEY (`id`) REFERENCES `named_secret` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
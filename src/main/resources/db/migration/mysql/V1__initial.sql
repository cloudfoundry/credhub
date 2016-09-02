-- MySQL dump 10.13  Distrib 5.7.14, for osx10.11 (x86_64)
--
-- Host: localhost    Database: credhub
-- ------------------------------------------------------
-- Server version	5.7.14

--
-- Table structure for table `auth_failure_audit_record`
--

CREATE TABLE `auth_failure_audit_record` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `failure_description` varchar(2000) DEFAULT NULL,
  `host_name` varchar(255) DEFAULT NULL,
  `now` datetime(3) DEFAULT NULL,
  `operation` varchar(255) DEFAULT NULL,
  `path` varchar(255) DEFAULT NULL,
  `requester_ip` varchar(255) DEFAULT NULL,
  `token_expires` bigint(20) NOT NULL,
  `token_issued` bigint(20) NOT NULL,
  `uaa_url` varchar(255) DEFAULT NULL,
  `user_id` varchar(255) DEFAULT NULL,
  `user_name` varchar(255) DEFAULT NULL,
  `x_forwarded_for` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `named_secret`
--

CREATE TABLE `named_secret` (
  `type` varchar(31) NOT NULL,
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `encrypted_value` blob,
  `name` varchar(255) NOT NULL,
  `nonce` tinyblob,
  `updated_at` bigint(20) NOT NULL,
  `uuid` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UK_iv5vf8iqm1sd3k3nacbm20ixp` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `certificate_secret`
--

CREATE TABLE `certificate_secret` (
  `ca` varchar(7000) DEFAULT NULL,
  `certificate` varchar(7000) DEFAULT NULL,
  `id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `FK34brqrqsrtkaf3gmty1rjkyjd` FOREIGN KEY (`id`) REFERENCES `named_secret` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `named_certificate_authority`
--

CREATE TABLE `named_certificate_authority` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `certificate` varchar(7000) DEFAULT NULL,
  `encrypted_value` blob,
  `name` varchar(255) NOT NULL,
  `nonce` tinyblob,
  `type` varchar(255) DEFAULT NULL,
  `updated_at` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UK_5ic6w4fi93q8y7xv7280yhsmr` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `operation_audit_record`
--

CREATE TABLE `operation_audit_record` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `host_name` varchar(255) DEFAULT NULL,
  `now` bigint(20) NOT NULL,
  `operation` varchar(255) DEFAULT NULL,
  `path` varchar(255) DEFAULT NULL,
  `requester_ip` varchar(255) DEFAULT NULL,
  `success` bit(1) NOT NULL,
  `token_expires` bigint(20) NOT NULL,
  `token_issued` bigint(20) NOT NULL,
  `uaa_url` varchar(255) DEFAULT NULL,
  `user_id` varchar(255) DEFAULT NULL,
  `user_name` varchar(255) DEFAULT NULL,
  `x_forwarded_for` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `password_secret`
--

CREATE TABLE `password_secret` (
  `id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `FK31hqe03pkugu8u5ng564ko2nv` FOREIGN KEY (`id`) REFERENCES `named_secret` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `value_secret`
--

CREATE TABLE `value_secret` (
  `id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `FKox93sy15f6pgbdr89kp05pnfq` FOREIGN KEY (`id`) REFERENCES `named_secret` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

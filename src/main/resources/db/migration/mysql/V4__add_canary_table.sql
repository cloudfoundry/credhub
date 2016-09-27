CREATE TABLE `named_canary` (
    `id` bigint(20) NOT NULL AUTO_INCREMENT,
    `encrypted_value` blob,
    `name` varchar(255) NOT NULL,
    `nonce` tinyblob,
    PRIMARY KEY (`id`)
);
ALTER TABLE certificate_credential
  ADD COLUMN `trusted_ca` TEXT(7000) DEFAULT NULL;

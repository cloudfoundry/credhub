ALTER TABLE named_secret
  RENAME TO credential;

ALTER TABLE certificate_secret
  RENAME TO certificate_credential;

ALTER TABLE ssh_secret
  RENAME TO ssh_credential;

ALTER TABLE rsa_secret
  RENAME TO rsa_credential;

ALTER TABLE user_secret
  RENAME TO user_credential;

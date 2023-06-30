ALTER TABLE credential
  RENAME TO credential_version;

ALTER TABLE credential_name
  RENAME TO credential;

ALTER TABLE password_secret
  RENAME TO password_credential;

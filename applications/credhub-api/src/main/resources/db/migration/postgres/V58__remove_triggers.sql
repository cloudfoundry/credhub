DROP FUNCTION IF EXISTS del_credential_version_encrypted_value();

DROP TRIGGER IF EXISTS tr_credential_version_post_del ON credential_version;

DROP FUNCTION IF EXISTS del_user_or_password_credential_encrypted_value();

DROP TRIGGER IF EXISTS tr_password_credential_post_del ON password_credential;

DROP TRIGGER IF EXISTS tr_user_credential_post_del ON user_credential;

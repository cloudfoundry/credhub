-- Delete the encrypted_value record that was associated
-- with the deleted credential_version record.
DROP TRIGGER IF EXISTS tr_credential_version_post_del;
CREATE TRIGGER tr_credential_version_post_del
AFTER DELETE ON credential_version
FOR EACH ROW CALL "org.cloudfoundry.credhub.data.CredentialVersionDeleteTrigger";

-- Delete the encrypted_value record that was associated
-- with the deleted password_credential record.
DROP TRIGGER IF EXISTS tr_password_credential_post_del;
CREATE TRIGGER tr_password_credential_post_del
AFTER DELETE ON password_credential
FOR EACH ROW CALL "org.cloudfoundry.credhub.data.PasswordOrUserCredentialDeleteTrigger";

-- Delete the encrypted_value record that was associated
-- with the deleted user_credential record.
DROP TRIGGER IF EXISTS tr_user_credential_post_del;
CREATE TRIGGER tr_user_credential_post_del
AFTER DELETE ON user_credential
FOR EACH ROW CALL "org.cloudfoundry.credhub.data.PasswordOrUserCredentialDeleteTrigger";

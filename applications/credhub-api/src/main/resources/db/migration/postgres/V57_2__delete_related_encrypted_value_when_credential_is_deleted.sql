-- Fix for https://github.com/cloudfoundry/credhub/issues/231

-- Delete the encrypted_values records that are associated
-- with the credential_version record when a credential_version was
-- deleted.

CREATE OR REPLACE FUNCTION del_credential_version_encrypted_value()
RETURNS TRiGGER AS $$
BEGIN
    DELETE FROM encrypted_value WHERE uuid = OLD.encrypted_value_uuid;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER tr_credential_version_post_del
AFTER DELETE ON credential_version
FOR EACH ROW EXECUTE FUNCTION del_credential_version_encrypted_value();

-- Delete the encrypted_values records that are associated
-- with the password_credential record or the user_credential record when the
-- credential record was deleted.

CREATE OR REPLACE FUNCTION del_user_or_password_credential_encrypted_value()
RETURNS TRiGGER AS $$
BEGIN
    DELETE FROM encrypted_value WHERE uuid = OLD.password_parameters_uuid;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER tr_password_credential_post_del
AFTER DELETE ON password_credential
FOR EACH ROW EXECUTE FUNCTION del_user_or_password_credential_encrypted_value();

CREATE OR REPLACE TRIGGER tr_user_credential_post_del
AFTER DELETE ON user_credential
FOR EACH ROW EXECUTE FUNCTION del_user_or_password_credential_encrypted_value();

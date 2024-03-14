-- Fix for https://github.com/cloudfoundry/credhub/issues/231

-- Trigger to delete encrypted_value records that are associated with
-- passowrd_credential or user_credential when a credential is deleted.
DROP TRIGGER IF EXISTS tr_credential_version_pre_del;
DELIMITER |
CREATE TRIGGER tr_credential_version_pre_del BEFORE DELETE ON credential_version
FOR EACH ROW
BEGIN
    DECLARE enc_val_id BINARY(16);

    -- For each record that is referencing encrypted_value record,
    -- set FKs to encrypted_value to null before deleting the encrypted_value
    -- record. Otherwise, the referencing record cannot be deleted because of
    -- the FK constraint.
    IF OLD.type = 'password' THEN
        SELECT password_parameters_uuid from password_credential
            WHERE uuid = OLD.uuid INTO enc_val_id;
        UPDATE password_credential SET password_parameters_uuid = NULL
            WHERE uuid = OLD.uuid;
        DELETE FROM encrypted_value WHERE uuid = enc_val_id;
    ELSEIF OLD.type = 'user' THEN
        SELECT password_parameters_uuid from user_credential
            WHERE uuid = OLD.uuid INTO enc_val_id;
        UPDATE user_credential SET password_parameters_uuid = NULL
            WHERE uuid = OLD.uuid;
        DELETE FROM encrypted_value WHERE uuid = enc_val_id;
    END IF;
END;
|
DELIMITER ;

-- Trigger to delete the encrypted_values records that are associated
-- with the credential_version record when a credential_version was
-- deleted.
DROP TRIGGER IF EXISTS tr_credential_version_post_del;
CREATE TRIGGER tr_credential_version_post_del AFTER DELETE ON credential_version
FOR EACH ROW
    -- Delete the encrypted_value record that is associated with the
    -- credential_version record.
    DELETE FROM encrypted_value WHERE uuid = OLD.encrypted_value_uuid;

-- Trigger to delete all associated encrypted_value records when a credential
-- is deleted. Needed to define one on credential table to work around the MySQL
-- trigger limitation where the triggers on cascade-deleted records are not
-- executed.
DROP TRIGGER IF EXISTS tr_credential_pre_del;
CREATE TRIGGER tr_credential_pre_del BEFORE DELETE ON credential
FOR EACH ROW
    -- Delete the child record here instead of relying on casecasde-delete, as
    -- MySQL trigger on the child table does not get executed when
    -- cascade-deleteed.
    DELETE FROM credential_version WHERE credential_uuid = OLD.uuid;

-- Fix for https://github.com/cloudfoundry/credhub/issues/231
-- Create delete trigger on credential table instead of the tables directly
-- reference encrypted_value table because the trigger does not work for
-- cascade-deleted records in MySQL.
DROP TRIGGER IF EXISTS tr_credential_deleted;
DELIMITER |
CREATE TRIGGER tr_credential_deleted BEFORE DELETE ON credential
FOR EACH ROW
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE cred_ver_id, enc_val_id BINARY(16);
    DECLARE cred_ver_type VARCHAR(31);
    DECLARE cur CURSOR FOR
        SELECT type, uuid FROM credential_version
            WHERE credential_uuid = OLD.uuid;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

    OPEN cur;
    read_loop: LOOP
        FETCH cur into cred_ver_type, cred_ver_id;
        IF done THEN
          LEAVE read_loop;
        END IF;

        -- For each talbe record that is referencing encrypted_value record,
        -- set FKs to encrypted_value to null before deleting the encrypted_value
        -- record. Otherwise, the referencing record cannot be deleted because of
        -- the FK constraint.

        -- Delete the encrypted_value record that is associated with the
        -- credential_version record.
        SELECT encrypted_value_uuid FROM credential_version
            WHERE uuid = cred_ver_id INTO enc_val_id;
        UPDATE credential_version SET encrypted_value_uuid = NULL
            WHERE uuid = cred_ver_id;
        DELETE FROM encrypted_value WHERE uuid = enc_val_id;
        SET enc_val_id = NULL;

        -- For password or user type credential, the password_credential
        -- or user_credential record also has associated encrypted_value record.
        -- Delete them, too.
        IF cred_ver_type = 'password' THEN
            SELECT password_parameters_uuid from password_credential
                WHERE uuid = cred_ver_id INTO enc_val_id;
            UPDATE password_credential SET password_parameters_uuid = NULL
                WHERE uuid = cred_ver_id;
            DELETE FROM encrypted_value WHERE uuid = enc_val_id;
        ELSEIF cred_ver_type = 'user' THEN
            SELECT password_parameters_uuid from user_credential
                WHERE uuid = cred_ver_id INTO enc_val_id;
            UPDATE user_credential SET password_parameters_uuid = NULL
                WHERE uuid = cred_ver_id;
            DELETE FROM encrypted_value WHERE uuid = enc_val_id;
        END IF;
    END LOOP read_loop;
    CLOSE cur;
END;
|
DELIMITER ;

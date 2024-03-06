-- Fix for https://github.com/cloudfoundry/credhub/issues/231
-- Create delete trigger on credential table instead of the tables directly
-- reference encrypted_value table because the trigger does not work for
-- cascade-deleted records in MySQL.
DROP TRIGGER IF EXISTS tr_credential_deleted;
DELIMITER |
CREATE TRIGGER tr_credential_deleted BEFORE DELETE ON credential
FOR EACH ROW
BEGIN
  DROP TEMPORARY TABLE IF EXISTS
    tmp_credential_version_uuids, tmp_encrypted_value_uuids;

  -- Remember the uuids of the credential_version records being deleted
  CREATE TEMPORARY TABLE tmp_credential_version_uuids
    SELECT uuid FROM credential_version
      WHERE credential_uuid = OLD.uuid;

  -- Remember the uuids of the encrypted_value records to delete
  CREATE TEMPORARY TABLE tmp_encrypted_value_uuids
    SELECT encrypted_value_uuid FROM credential_version
      WHERE credential_uuid = OLD.uuid;
  INSERT INTO tmp_encrypted_value_uuids (encrypted_value_uuid)
    SELECT password_parameters_uuid from password_credential
      WHERE password_credential.uuid IN
        (SELECT uuid FROM tmp_credential_version_uuids);
  INSERT INTO tmp_encrypted_value_uuids (encrypted_value_uuid)
    SELECT password_parameters_uuid from user_credential
      WHERE user_credential.uuid IN
        (SELECT uuid FROM tmp_credential_version_uuids);

  -- Set FKs to encrypted_value to null so the encrypted_value
  -- record can be deleted without violating the FK constraint
  UPDATE credential_version SET encrypted_value_uuid = NULL
    WHERE credential_uuid = OLD.uuid;
  UPDATE password_credential SET password_parameters_uuid = NULL
    WHERE password_credential.uuid IN
      (SELECT uuid FROM tmp_credential_version_uuids);
  UPDATE user_credential SET password_parameters_uuid = NULL
    WHERE user_credential.uuid IN
      (SELECT uuid FROM tmp_credential_version_uuids);

  -- Delete the encrypted_value records
  DELETE FROM encrypted_value WHERE encrypted_value.uuid IN
    (SELECT encrypted_value_uuid from tmp_encrypted_value_uuids);

  DROP TEMPORARY TABLE IF EXISTS
    tmp_credential_version_uuids, tmp_encrypted_value_uuids;
END;
|
DELIMITER ;

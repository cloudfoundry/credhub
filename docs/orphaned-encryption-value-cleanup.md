## Cleaning up orphaned encrypted_value records
CredHub version 2.12.66 and earlier had a bug where `encrypted_value`
records were not deleted when the associated credentials were deleted.
(See https://github.com/cloudfoundry/credhub/issues/231.)

To clean up the orphaned `encrypted_value` records that accumulated
on these older CredHub versions, run the SQL script below for your database type.

### For postgresql database
``` sql
-- Step 1: Create indexes on the 3 related tables
CREATE INDEX CONCURRENTLY IF NOT EXISTS credential_version_encrypted_value_uuid_idx ON credential_version USING btree (encrypted_value_uuid);
CREATE INDEX CONCURRENTLY IF NOT EXISTS password_credential_password_parameters_uuid_idx ON password_credential USING btree (password_parameters_uuid);
CREATE INDEX CONCURRENTLY IF NOT EXISTS user_credential_password_parameters_uuid_idx ON user_credential USING btree (password_parameters_uuid);

-- Step 2: Optional. Get the number of encrypted_value records that are not in any of those 3 tables
SELECT count(*)  FROM encrypted_value
WHERE
    NOT EXISTS (select 1 from credential_version where encrypted_value_uuid=encrypted_value.uuid)
AND
    NOT EXISTS (select 1 from password_credential where password_parameters_uuid=encrypted_value.uuid)
AND
    NOT EXISTS (select 1 from user_credential where password_parameters_uuid=encrypted_value.uuid);

-- Step 3: Delete encrypted_value records that are not in any of those 3 tables
DELETE FROM encrypted_value
WHERE
    NOT EXISTS (select 1 from credential_version where encrypted_value_uuid=encrypted_value.uuid)
AND
    NOT EXISTS (select 1 from password_credential where password_parameters_uuid=encrypted_value.uuid)
AND
    NOT EXISTS (select 1 from user_credential where password_parameters_uuid=encrypted_value.uuid);

-- Step 4: Drop the indexes
DROP INDEX CONCURRENTLY IF EXISTS credential_version_encrypted_value_uuid_idx;
DROP INDEX CONCURRENTLY IF EXISTS password_credential_password_parameters_uuid_idx;
DROP INDEX CONCURRENTLY IF EXISTS user_credential_password_parameters_uuid_idx;

```
Note that adding indexes and running the queries may take a very long time if you
have a large CredHub database. You may want to run each query separately. In
particular, you may want to count the number of orphaned records first to
determine whether cleaning them up will reduce the size of your CredHub
database significantly.

### For MySQL or MySQL-compatible databases, such as MariaDB
``` sql
-- Step 1: Optional. Get the number of encrypted_value records that are not in any of those 3 tables
SELECT count(*)  FROM encrypted_value
WHERE
    NOT EXISTS (select 1 from credential_version where encrypted_value_uuid=encrypted_value.uuid)
AND
    NOT EXISTS (select 1 from password_credential where password_parameters_uuid=encrypted_value.uuid)
AND
    NOT EXISTS (select 1 from user_credential where password_parameters_uuid=encrypted_value.uuid);

-- Step 2: Delete encrypted_value records that are not in any of the 3 related tables
DELETE FROM encrypted_value
WHERE
NOT EXISTS (select 1 from credential_version where encrypted_value_uuid=encrypted_value.uuid)
AND
NOT EXISTS (select 1 from password_credential where password_parameters_uuid=encrypted_value.uuid)
AND
NOT EXISTS (select 1 from user_credential where password_parameters_uuid=encrypted_value.uuid);
```
For MySQL database, the necessary indexes are already there, so you do not have
to create them. The queries still may take a long time to run if you have a large
database. You may want to get the number of orphaned records before proceeding
to the deletion step.
## Cleaning up orphaned encrypted_value records
CredHub version 2.12.66 and ealier had a bug where associated `encrypted_value`
records were not deleted when credentials were deleted.
(See https://github.com/cloudfoundry/credhub/issues/231.)

To clean up those orphaned encrypted_value records accumulated in the old
credhub versions, you can run SQL script for your database type as
described below.

### For postgresql database
``` sql
-- Step 1: Create indexes on the 3 related tables
CREATE INDEX CONCURRENTLY IF NOT EXISTS credential_version_encrypted_value_uuid_idx ON credential_version USING btree (encrypted_value_uuid);
CREATE INDEX CONCURRENTLY IF NOT EXISTS password_credential_password_parameters_uuid_idx ON password_credential USING btree (password_parameters_uuid);
CREATE INDEX CONCURRENTLY IF NOT EXISTS user_credential_password_parameters_uuid_idx ON user_credential USING btree (password_parameters_uuid);

-- Step 2: Optoinal. Get the number of encrypted_value records that are not in any of those 3 tables
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
Note that adding indexes and running the queries may take very long time if you
have large database. You may want to run each step one by one before proceeding
to next step, to get the number of orphaned records before proceeding to
next step for example.

### For mysql database
``` sql
-- Step 1: Optoinal. Get the number of encrypted_value records that are not in any of those 3 tables
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
to create them. The queries still may take a long time to run if you have large
database. You may want to get the number of orphaned records before proceeding
to next step.
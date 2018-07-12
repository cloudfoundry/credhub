ALTER TABLE permission
  ADD COLUMN path VARCHAR(255);
UPDATE permission
SET path = (select name
            from credential
            where uuid = permission.credential_uuid);

ALTER TABLE permission
  DROP FOREIGN KEY credential_uuid_access_fkey;

ALTER TABLE permission
  DROP INDEX actor_resource_unique;

ALTER TABLE permission
  DROP COLUMN credential_uuid;

ALTER TABLE permission
  MODIFY path VARCHAR(255) NOT NULL;

CREATE UNIQUE INDEX permission_path_actor_uindex ON permission (path, actor);
/*
In H2 and Postgres, this is where we update our CHECK constraint on the
permissible values for auth_method.

Turns out that MySQL silently ignores CHECK constraints, so all we do here
is change the default value.

See https://dev.mysql.com/doc/refman/5.7/en/create-table.html (search for CHECK)
*/

ALTER TABLE `operation_audit_record`
  MODIFY `auth_method`
  VARCHAR(10) DEFAULT 'unknown' NOT NULL;

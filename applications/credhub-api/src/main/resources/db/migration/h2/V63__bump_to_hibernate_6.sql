-- Workaround for schema-validation errors such as:
-- wrong column type encountered in column [uuid] in table [ssh_credential];
-- found [binary (Types#BINARY)], but expecting [varbinary (Types#UUID)]
alter table certificate_credential alter column uuid varbinary not null;
alter table credential alter column uuid varbinary not null;
alter table credential_version alter column uuid varbinary not null;
alter table credential_version alter column credential_uuid varbinary not null;
alter table credential_version alter column encrypted_value_uuid varbinary not null;
alter table encrypted_value alter column uuid varbinary not null;
alter table encrypted_value alter column encryption_key_uuid varbinary not null;
alter table encryption_key_canary alter column uuid varbinary not null;
alter table password_credential alter column uuid varbinary not null;
alter table password_credential alter column password_parameters_uuid varbinary not null;
alter table permission alter column uuid varbinary not null;
alter table rsa_credential alter column uuid varbinary not null;
alter table ssh_credential alter column uuid varbinary not null;
alter table user_credential alter column uuid varbinary not null;
alter table user_credential alter column password_parameters_uuid varbinary not null;

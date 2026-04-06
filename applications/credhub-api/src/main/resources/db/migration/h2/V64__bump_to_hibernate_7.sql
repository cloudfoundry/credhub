-- Workaround for schema-validation errors such as:
-- wrong column type encountered in column [uuid] in table [certificate_credential];
-- found [binary varying (Types#VARBINARY)], but expecting [uuid (Types#UUID)]
-- Hibernate 7 (Spring Boot 4) maps Java UUID to H2's native UUID type instead of VARBINARY.
alter table certificate_credential alter column uuid uuid not null;
alter table credential alter column uuid uuid not null;
alter table credential_version alter column uuid uuid not null;
alter table credential_version alter column credential_uuid uuid not null;
alter table credential_version alter column encrypted_value_uuid uuid;
alter table encrypted_value alter column uuid uuid not null;
alter table encrypted_value alter column encryption_key_uuid uuid not null;
alter table encryption_key_canary alter column uuid uuid not null;
alter table password_credential alter column uuid uuid not null;
alter table password_credential alter column password_parameters_uuid uuid;
alter table permission alter column uuid uuid not null;
alter table rsa_credential alter column uuid uuid not null;
alter table ssh_credential alter column uuid uuid not null;
alter table user_credential alter column uuid uuid not null;
alter table user_credential alter column password_parameters_uuid uuid;

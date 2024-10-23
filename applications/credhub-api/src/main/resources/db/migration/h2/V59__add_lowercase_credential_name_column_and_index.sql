ALTER TABLE credential
    ADD COLUMN name_lowercase VARCHAR(1024) AS LOWER(name);

CREATE INDEX credential_name_lowercase
    ON credential(name_lowercase);
ALTER TABLE credential
    ADD COLUMN name_lowercase VARCHAR(1024) GENERATED ALWAYS AS (lower(name)) STORED;
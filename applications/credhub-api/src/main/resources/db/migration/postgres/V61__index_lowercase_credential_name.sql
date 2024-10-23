CREATE INDEX CONCURRENTLY IF NOT EXISTS credential_name_lowercase
    ON credential(name_lowercase);
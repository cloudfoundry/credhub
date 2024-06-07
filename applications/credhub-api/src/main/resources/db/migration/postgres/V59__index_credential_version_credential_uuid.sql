CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_credential_version_credential_uuid
    ON credential_version(credential_uuid);

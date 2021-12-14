package org.cloudfoundry.credhub.config;

import java.sql.SQLException;

public interface DatabaseLayer {
    boolean schemaVersionTableExists() throws SQLException;
    boolean flywaySchemaHistoryTableExists();
    boolean backupSchemaVersionExists();
    void renameSchemaVersionAsBackupSchemaVersion();
    void renameSchemaVersionAsFlywaySchemaHistory();
}

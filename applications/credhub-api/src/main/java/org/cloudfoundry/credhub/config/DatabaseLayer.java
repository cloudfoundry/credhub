package org.cloudfoundry.credhub.config;

import java.sql.SQLException;

public interface DatabaseLayer {
    boolean oldFlywayMigrationTableExists() throws SQLException;
    boolean newFlywayMigrationTableExists() throws SQLException;
    void updateOldMigrationTableName() throws SQLException;
}

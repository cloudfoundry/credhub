package org.cloudfoundry.credhub.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class DatatabaseLayerImpl implements DatabaseLayer {
    static final String OLD_HISTORY_TABLE_NAME = "schema_version";
    static final String NEW_HISTORY_TABLE_NAME = "flyway_schema_history";
    private final Connection connection;

    private static final Logger LOGGER = LogManager.getLogger(DatatabaseLayerImpl.class.getName());

    public DatatabaseLayerImpl(Connection connection) {
        this.connection = connection;
    }

    @Override
    public boolean oldFlywayMigrationTableExists() throws SQLException {
        return tableExists(OLD_HISTORY_TABLE_NAME, connection);
    }

    @Override
    public boolean newFlywayMigrationTableExists() throws SQLException {
        return tableExists(NEW_HISTORY_TABLE_NAME, connection);
    }

    private boolean tableExists(String tableName, Connection connection) throws SQLException {
        ResultSet resultSet = connection.getMetaData().getTables(null, null, tableName, new String[]{"TABLE"});
        boolean exists = resultSet.next();
        LOGGER.info(String.format("Checking for existence of '%s' table: %s", tableName, exists));
        return exists;
    }

    @Override
    public void updateOldMigrationTableName() throws SQLException {
        LOGGER.info("Renaming 'schema_version' migration table to 'flyway_schema_history'");
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("ALTER TABLE " + OLD_HISTORY_TABLE_NAME + " RENAME TO " + NEW_HISTORY_TABLE_NAME);
        }
    }
}

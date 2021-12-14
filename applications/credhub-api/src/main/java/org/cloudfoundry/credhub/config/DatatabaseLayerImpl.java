package org.cloudfoundry.credhub.config;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

public class DatatabaseLayerImpl implements DatabaseLayer, AutoCloseable {
    public static final String OLD_HISTORY_TABLE_NAME = "schema_version";
    private final Connection connection;

    public DatatabaseLayerImpl(Connection connection) {
        this.connection = connection;
    }

    @Override
    public boolean schemaVersionTableExists() throws SQLException {
        return tableExists(OLD_HISTORY_TABLE_NAME, connection);
    }

    @Override
    public boolean flywaySchemaHistoryTableExists() {
        return false;
    }

    @Override
    public boolean backupSchemaVersionExists() {
        return false;
    }

    private boolean tableExists(String tableName, Connection connection) throws SQLException {
        ResultSet resultSet = connection.getMetaData().getTables(null, null, tableName, new String[]{"TABLE"});
        return resultSet.next();
    }

    @Override
    public void renameSchemaVersionAsBackupSchemaVersion() {

    }

    @Override
    public void renameSchemaVersionAsFlywaySchemaHistory() {

    }

    @Override
    public void close() throws Exception {
        connection.close();
    }
}

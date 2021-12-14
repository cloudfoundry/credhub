package org.cloudfoundry.credhub.config;

import org.flywaydb.core.Flyway;
import org.junit.Before;
import org.junit.Test;

import java.sql.*;

import static org.cloudfoundry.credhub.config.DatatabaseLayerImpl.NEW_HISTORY_TABLE_NAME;
import static org.cloudfoundry.credhub.config.DatatabaseLayerImpl.OLD_HISTORY_TABLE_NAME;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class FlywayMigrationStrategyConfigurationTest {
    FlywayMigrationStrategyConfiguration instanceToTest;
    private Connection mockConnection;
    private Flyway mockFlyway;
    private DatabaseMetaData mockDatabaseMetaData;
    private Statement mockStatement;
    private ResultSet mockResultSetLegacyTable;
    private ResultSet mockResultSetNewTable;

    @Before
    public void setUp() throws Exception {
        instanceToTest = spy(FlywayMigrationStrategyConfiguration.class);

        mockConnection = mock(Connection.class);
        mockDatabaseMetaData = mock(DatabaseMetaData.class);
        mockStatement = mock(Statement.class);
        mockResultSetLegacyTable = mock(ResultSet.class);
        mockResultSetNewTable = mock(ResultSet.class);

        when(mockStatement.execute(any())).thenReturn(false);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
    }

    @Test
    public void doesNotRenameIfOnlyNewTableExists() throws SQLException {
        mockTableExistenceInDB(OLD_HISTORY_TABLE_NAME, false, mockResultSetLegacyTable);
        mockTableExistenceInDB(NEW_HISTORY_TABLE_NAME, true, mockResultSetNewTable);
        when(mockConnection.getMetaData()).thenReturn(mockDatabaseMetaData);
        doReturn(mockConnection).when(instanceToTest).getConnection(any());

        instanceToTest.renameMigrationTableIfNeeded(mockFlyway);

        verify(mockStatement, times(0)).execute(any());
    }

    @Test
    public void renameLegacyTableToNewIfOnlyLegacyTableExists() throws SQLException {
        mockTableExistenceInDB(OLD_HISTORY_TABLE_NAME, true, mockResultSetLegacyTable);
        mockTableExistenceInDB(NEW_HISTORY_TABLE_NAME, false, mockResultSetNewTable);
        when(mockConnection.getMetaData()).thenReturn(mockDatabaseMetaData);
        doReturn(mockConnection).when(instanceToTest).getConnection(any());

        instanceToTest.renameMigrationTableIfNeeded(mockFlyway);

        verify(mockStatement, times(1)).execute(eq("ALTER TABLE schema_version RENAME TO flyway_schema_history"));
    }

    private void mockTableExistenceInDB(String tableName, boolean tableExists, ResultSet mockResultSetLegacyTable) throws SQLException {
        when(mockResultSetLegacyTable.next()).thenReturn(tableExists);
        when(mockDatabaseMetaData.getTables(isNull(), isNull(), eq(tableName), any())).thenReturn(mockResultSetLegacyTable);
    }
}
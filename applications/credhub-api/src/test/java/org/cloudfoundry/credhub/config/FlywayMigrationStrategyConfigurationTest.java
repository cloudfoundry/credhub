package org.cloudfoundry.credhub.config;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.junit.Before;
import org.junit.Test;

import java.sql.*;

import static org.cloudfoundry.credhub.config.DatatabaseLayerImpl.NEW_HISTORY_TABLE_NAME;
import static org.cloudfoundry.credhub.config.DatatabaseLayerImpl.OLD_HISTORY_TABLE_NAME;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class FlywayMigrationStrategyConfigurationTest {
    private FlywayMigrationStrategyConfiguration instanceToTest;
    private Connection mockConnection;
    private Flyway mockFlyway;
    private DatabaseMetaData mockDatabaseMetaData;
    private Statement mockStatement;
    private ResultSet mockResultSetLegacyTable;
    private ResultSet mockResultSetNewTable;

    @Before
    public void setUp() throws Exception {
        instanceToTest = spy(FlywayMigrationStrategyConfiguration.class);

        mockFlyway = mock(Flyway.class);
        mockConnection = mock(Connection.class);
        mockDatabaseMetaData = mock(DatabaseMetaData.class);
        mockStatement = mock(Statement.class);
        mockResultSetLegacyTable = mock(ResultSet.class);
        mockResultSetNewTable = mock(ResultSet.class);

        when(mockStatement.execute(any())).thenReturn(false);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockConnection.getMetaData()).thenReturn(mockDatabaseMetaData);
        doReturn(mockConnection).when(instanceToTest).getConnection(any());
    }

    @Test
    public void doesNotRenameIfOnlyNewTableExists() throws SQLException {
        mockOldTableExistenceInDB(false);
        mockNewTableExistenceInDB(true);

        instanceToTest.renameMigrationTableIfNeeded(mockFlyway);

        verify(mockStatement, times(0)).execute(any());
    }

    @Test
    public void doNothingIfBothTablesExist() throws SQLException {
        mockOldTableExistenceInDB(true);
        mockNewTableExistenceInDB(true);

        instanceToTest.renameMigrationTableIfNeeded(mockFlyway);

        verify(mockStatement, times(0)).execute(any());
    }

    @Test
    public void renameLegacyTableToNewIfOnlyLegacyTableExists() throws SQLException {
        mockOldTableExistenceInDB(true);
        mockNewTableExistenceInDB(false);

        instanceToTest.renameMigrationTableIfNeeded(mockFlyway);

        verify(mockStatement, times(1)).execute(eq("ALTER TABLE schema_version RENAME TO flyway_schema_history"));
        verify(mockConnection, times(1)).close();
    }

    @Test(expected = FlywayException.class)
    public void handlesGetConnectionException() throws SQLException {
        doThrow(SQLException.class).when(instanceToTest).getConnection(any());

        instanceToTest.renameMigrationTableIfNeeded(mockFlyway);
    }

    @Test
    public void handlesExecuteException() throws SQLException {
        mockOldTableExistenceInDB(true);
        mockNewTableExistenceInDB(false);
        when(mockStatement.execute(any())).thenThrow(SQLException.class);

        try {
            instanceToTest.renameMigrationTableIfNeeded(mockFlyway);
        } catch (FlywayException e) {
            return;
        } finally {
            verify(mockConnection, times(1)).close();
        }
        fail("Expected FlywayException");
    }

    private void mockNewTableExistenceInDB(boolean tableExists) throws SQLException {
        when(mockResultSetNewTable.next()).thenReturn(tableExists);
        when(mockDatabaseMetaData.getTables(isNull(), isNull(), eq(NEW_HISTORY_TABLE_NAME), any()))
                .thenReturn(mockResultSetNewTable);
    }

    private void mockOldTableExistenceInDB(boolean tableExists) throws SQLException {
        when(mockResultSetLegacyTable.next()).thenReturn(tableExists);
        when(mockDatabaseMetaData.getTables(isNull(), isNull(), eq(OLD_HISTORY_TABLE_NAME), any()))
                .thenReturn(mockResultSetLegacyTable);
    }
}
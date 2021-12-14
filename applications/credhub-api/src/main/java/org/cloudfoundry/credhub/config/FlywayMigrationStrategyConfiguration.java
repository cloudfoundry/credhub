package org.cloudfoundry.credhub.config;

import com.google.common.annotations.VisibleForTesting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.jetbrains.annotations.NotNull;
import org.springframework.boot.autoconfigure.flyway.FlywayMigrationStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

@Configuration
public class FlywayMigrationStrategyConfiguration {

    private static final Logger LOGGER = LogManager.getLogger(FlywayMigrationStrategyConfiguration.class.getName());

    @Bean
    public FlywayMigrationStrategy repairBeforeMigration() {
        return flyway -> {
            renameMigrationTableIfNeeded(flyway);
            repairIfNecessary(flyway);
            runMigration(flyway);
        };
    }

    @VisibleForTesting
    void renameMigrationTableIfNeeded(@NotNull Flyway flyway) {
        try (Connection connection = flyway.getConfiguration().getDataSource().getConnection()) {
            DatabaseLayer databaseLayer = new DatatabaseLayerImpl(connection);
            LOGGER.info("Checking for existence of older 'schema_version' migration table");
            if (databaseLayer.schemaVersionTableExists()) {
                if (databaseLayer.flywaySchemaHistoryTableExists()) {
                    if (databaseLayer.backupSchemaVersionTableExists()) {
                        LOGGER.warn("For unknown reasons, 'schema_version', 'backup_schema_version' and 'flyway_schema_history' all exist, not performing any renaming");
                    } else {
                        LOGGER.warn("Both 'schema_version' and 'flyway_schema_history' exist, renaming the 'schema_version' to 'backup_schema_version'");
                        try (Statement stmt = connection.createStatement()) {
                            stmt.execute("ALTER TABLE schema_version RENAME TO backup_schema_version");
                        }
                    }
                } else {
                    LOGGER.info("Renaming 'schema_version' migration table to 'flyway_schema_history'");
                    try (Statement stmt = connection.createStatement()) {
                        stmt.execute("ALTER TABLE schema_version RENAME TO flyway_schema_history");
                    }
                }
            }
        } catch (SQLException ex) {
            LOGGER.fatal("Error renaming migration table.");
            throw new FlywayException("Error renaming migration table", ex);
        }
    }

    private boolean tableExists(String tableName, Connection connection) throws SQLException {
        ResultSet resultSet = connection.getMetaData().getTables(null, null, tableName, new String[]{"TABLE"});
        return resultSet.next();
    }

    private void repairIfNecessary(@NotNull Flyway flyway) {
        try {
            LOGGER.info("Validating database state...");
            flyway.validate();
            LOGGER.info("Validation successful.");
        } catch (FlywayException e) {
            try {
                LOGGER.warn(
                        String.format(
                                "Validation failed: \"%s\".",
                                e.getMessage()
                        )
                );
                LOGGER.info("Attempting to repair...");
                flyway.repair();
                LOGGER.info("Repair succeeded.");
            } catch (FlywayException ex) {
                LOGGER.fatal("Couldn't repair database. Crashing.");
                throw ex;
            }
        }
    }

    private void runMigration(@NotNull Flyway flyway) {
        try {
            LOGGER.info("Running FlyWay migration....");
            flyway.migrate();
            LOGGER.info("FlyWay migration successful.");
        } catch (FlywayException e) {
            LOGGER.fatal("FlyWay migration failed. Crashing.");
            throw e;
        }
    }
}

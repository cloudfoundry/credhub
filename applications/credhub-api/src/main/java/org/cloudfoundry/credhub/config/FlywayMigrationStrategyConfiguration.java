package org.cloudfoundry.credhub.config;

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

    private void renameMigrationTableIfNeeded(@NotNull Flyway flyway) {
        try (Connection connection = flyway.getConfiguration().getDataSource().getConnection()) {
            LOGGER.info("Checking for existence of older 'schema_version' migration table");
            ResultSet tables = connection.getMetaData().getTables(null, null, "schema_version", new String[]{"TABLE"});
            if (tables.next()) {
                LOGGER.info("Renaming 'schema_version' migration table to 'flyway_schema_history'");
                try (Statement stmt = connection.createStatement()) {
                    stmt.execute("ALTER TABLE schema_version RENAME TO flyway_schema_history");
                }
            }
        } catch (SQLException ex) {
            LOGGER.fatal("Error renaming migration table.");
            throw new FlywayException("Error renaming migration table", ex);
        }
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

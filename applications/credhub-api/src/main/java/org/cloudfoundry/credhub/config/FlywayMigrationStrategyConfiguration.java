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
import java.sql.SQLException;

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
        try (Connection connection = getConnection(flyway)) {
            DatabaseLayer databaseLayer = new DatatabaseLayerImpl(connection);
            if (databaseLayer.oldFlywayMigrationTableExists() &&
                    !databaseLayer.newFlywayMigrationTableExists()) {
                databaseLayer.updateOldMigrationTableName();
            }
        } catch (SQLException ex) {
            LOGGER.fatal("Error renaming migration table.");
            throw new FlywayException("Error renaming migration table", ex);
        }
    }

    @VisibleForTesting
    Connection getConnection(@NotNull Flyway flyway) throws SQLException {
        return flyway.getConfiguration().getDataSource().getConnection();
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

package org.cloudfoundry.credhub.config;

import org.flywaydb.core.api.CoreErrorCode;
import org.flywaydb.core.api.FlywayException;
import org.flywaydb.database.postgresql.PostgreSQLConfigurationExtension;
import org.flywaydb.database.postgresql.PostgreSQLDatabaseType;
import org.springframework.boot.autoconfigure.flyway.FlywayMigrationStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FlywayMigrationStrategyTestConfig {
    @Bean
    public FlywayMigrationStrategy repairBeforeMigration() {
        return flyway -> {
            if (flyway.getConfiguration().getDatabaseType() instanceof
                    PostgreSQLDatabaseType) {
                // For CREATE INDEX CONCURRENTLY. See
                // https://documentation.red-gate.com/fd/flyway-postgresql-transactional-lock-setting-277579114.html.
                flyway.getConfigurationExtension(
                        PostgreSQLConfigurationExtension.class).setTransactionalLock(
                        false);
            }

            try {
                flyway.migrate();
            }
            catch (FlywayException e) {
                if (CoreErrorCode.DUPLICATE_VERSIONED_MIGRATION == e.getErrorCode()) {
                    // Some tests get this error because the db migration script
                    // folders are included in more than once in the classpath.
                    System.err.println(e.getMessage());
                }
                else {
                    throw e;
                }
            }
        };
    }
}

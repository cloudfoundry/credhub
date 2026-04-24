package org.cloudfoundry.credhub.config;

import org.springframework.boot.flyway.autoconfigure.FlywayConfigurationCustomizer;
import org.springframework.boot.flyway.autoconfigure.FlywayMigrationStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.flywaydb.core.api.CoreErrorCode;
import org.flywaydb.core.api.FlywayException;
import org.flywaydb.database.postgresql.PostgreSQLConfigurationExtension;

@Configuration
public class FlywayMigrationStrategyTestConfig {
    @Bean
    public FlywayConfigurationCustomizer postgresFlywayCustomizer() {
        return configuration -> {
            // For CREATE INDEX CONCURRENTLY. See
            // https://documentation.red-gate.com/fd/flyway-postgresql-transactional-lock-setting-277579114.html.
            configuration.getConfigurationExtension(
                    PostgreSQLConfigurationExtension.class).setTransactionalLock(
                    false);
        };
    }

    @Bean
    public FlywayMigrationStrategy repairBeforeMigration() {
        return flyway -> {
            try {
                flyway.migrate();
            } catch (FlywayException e) {
                if (CoreErrorCode.DUPLICATE_VERSIONED_MIGRATION == e.getErrorCode()) {
                    // Some tests get this error because the db migration script
                    // folders are included in more than once in the classpath.
                    System.err.println(e.getMessage());
                } else {
                    throw e;
                }
            }
        };
    }
}

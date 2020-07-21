package org.cloudfoundry.credhub.config;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.jetbrains.annotations.NotNull;
import org.springframework.boot.autoconfigure.flyway.FlywayMigrationStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FlywayMigrationStrategyConfiguration {

    @Bean
    public FlywayMigrationStrategy repairBeforeMigration() {
        return flyway -> {
            repairIfNecessary(flyway);
            flyway.migrate();
        };
    }

    private void repairIfNecessary(@NotNull Flyway flyway) {
        try {
            flyway.validate();
        } catch (FlywayException e) {
            flyway.repair();
        }
    }
}

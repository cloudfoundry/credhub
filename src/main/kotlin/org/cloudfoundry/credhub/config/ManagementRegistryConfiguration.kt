package org.cloudfoundry.credhub.config

import org.cloudfoundry.credhub.registry.ManagementRegistry
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ManagementRegistryConfiguration {
    @Bean
    fun getManagementRegistry(): ManagementRegistry {
        return ManagementRegistry()
    }
}

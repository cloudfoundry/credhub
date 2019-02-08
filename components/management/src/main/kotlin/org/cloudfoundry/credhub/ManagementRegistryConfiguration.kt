package org.cloudfoundry.credhub

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ManagementRegistryConfiguration {
    @Bean
    fun getManagementRegistry(): ManagementRegistry {
        return ManagementRegistry()
    }
}

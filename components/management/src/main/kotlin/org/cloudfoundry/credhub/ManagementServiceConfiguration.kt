package org.cloudfoundry.credhub

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class ManagementServiceConfiguration {

    @Bean
    fun getManagementService(managementRegistry: ManagementRegistry): ManagementService {
        return DefaultManagementService(managementRegistry)
    }
}

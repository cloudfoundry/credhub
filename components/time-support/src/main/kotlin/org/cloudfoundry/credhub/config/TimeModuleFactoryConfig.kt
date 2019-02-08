package org.cloudfoundry.credhub.config

import com.fasterxml.jackson.databind.Module
import org.cloudfoundry.credhub.util.TimeModuleFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class TimeModuleFactoryConfig {
    @Bean
    fun javaTimeModule(): Module {
        return TimeModuleFactory.createTimeModule()
    }
}

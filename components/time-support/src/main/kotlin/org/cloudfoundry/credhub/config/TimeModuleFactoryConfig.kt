package org.cloudfoundry.credhub.config

import org.cloudfoundry.credhub.util.TimeModuleFactory
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import tools.jackson.databind.JacksonModule

@Configuration
class TimeModuleFactoryConfig {
    @Bean
    fun javaTimeModule(): JacksonModule = TimeModuleFactory.createTimeModule()
}

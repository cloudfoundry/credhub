package org.cloudfoundry.credhub

import com.fasterxml.jackson.databind.Module
import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.module.kotlin.KotlinModule
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder

@Configuration
class ObjectMapperConfig {
    @Bean
    fun jacksonBuilder(javaTimeModule: Module): Jackson2ObjectMapperBuilder {
        return Jackson2ObjectMapperBuilder().apply {
            modules(javaTimeModule, KotlinModule() as Module?)
            failOnUnknownProperties(true)
            propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
        }
    }
}

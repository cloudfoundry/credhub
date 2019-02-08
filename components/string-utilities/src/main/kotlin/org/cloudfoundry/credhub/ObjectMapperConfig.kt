package org.cloudfoundry.credhub

import com.fasterxml.jackson.databind.Module
import com.fasterxml.jackson.databind.PropertyNamingStrategy
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder

@Configuration
class ObjectMapperConfig {
    @Bean
    fun jacksonBuilder(javaTimeModule: Module): Jackson2ObjectMapperBuilder {
        val builder = Jackson2ObjectMapperBuilder()
        builder.modules(javaTimeModule)
        builder.failOnUnknownProperties(true)
        builder.propertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE)
        return builder
    }
}

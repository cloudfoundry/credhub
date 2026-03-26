package org.cloudfoundry.credhub

import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import tools.jackson.databind.DeserializationFeature
import tools.jackson.databind.JacksonModule
import tools.jackson.databind.PropertyNamingStrategies
import tools.jackson.module.kotlin.KotlinModule

@Configuration
class ObjectMapperConfig {
    @Bean
    fun jacksonCustomizer(javaTimeModule: JacksonModule): JsonMapperBuilderCustomizer =
        JsonMapperBuilderCustomizer { builder ->
            builder.addModule(javaTimeModule)
            builder.addModule(KotlinModule.Builder().build())
            builder.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            builder.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
        }
}

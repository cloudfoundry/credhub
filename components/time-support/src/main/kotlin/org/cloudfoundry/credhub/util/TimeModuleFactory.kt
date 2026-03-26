package org.cloudfoundry.credhub.util

import tools.jackson.core.JsonGenerator
import tools.jackson.databind.JacksonModule
import tools.jackson.databind.SerializationContext
import tools.jackson.databind.ValueSerializer
import tools.jackson.databind.module.SimpleModule
import java.time.Instant
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter.ofPattern

class TimeModuleFactory private constructor() {
    companion object {
        private val TIMESTAMP_FORMAT = ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")

        fun createTimeModule(): JacksonModule {
            val module = SimpleModule("CredhubTimeModule")

            module.addSerializer(
                Instant::class.java,
                object : ValueSerializer<Instant>() {
                    override fun serialize(
                        value: Instant,
                        gen: JsonGenerator,
                        serializers: SerializationContext,
                    ) {
                        gen.writeString(ZonedDateTime.ofInstant(value, ZoneId.of("UTC")).format(TIMESTAMP_FORMAT))
                    }
                },
            )

            return module
        }
    }
}

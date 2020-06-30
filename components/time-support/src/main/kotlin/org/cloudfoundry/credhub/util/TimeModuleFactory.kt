package org.cloudfoundry.credhub.util

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import java.io.IOException
import java.time.Instant
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter.ofPattern

class TimeModuleFactory private constructor() {
    companion object {

        private val TIMESTAMP_FORMAT = ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")

        fun createTimeModule(): JavaTimeModule {
            val javaTimeModule = JavaTimeModule()

            javaTimeModule.addSerializer(
                Instant::class.java,
                object : JsonSerializer<Instant>() {
                    @Throws(IOException::class)
                    override fun serialize(value: Instant, gen: JsonGenerator, serializers: SerializerProvider) {
                        gen.writeString(ZonedDateTime.ofInstant(value, ZoneId.of("UTC")).format(TIMESTAMP_FORMAT))
                    }
                }
            )

            return javaTimeModule
        }
    }
}

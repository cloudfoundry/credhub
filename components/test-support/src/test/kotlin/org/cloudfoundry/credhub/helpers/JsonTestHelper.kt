package org.cloudfoundry.credhub.helpers

import jakarta.validation.ConstraintViolation
import jakarta.validation.Validation
import org.cloudfoundry.credhub.util.TimeModuleFactory
import org.hamcrest.BaseMatcher
import org.hamcrest.Description
import org.hamcrest.Matcher
import tools.jackson.core.JacksonException
import tools.jackson.databind.DeserializationFeature
import tools.jackson.databind.JsonNode
import tools.jackson.databind.PropertyNamingStrategies
import tools.jackson.databind.json.JsonMapper

class JsonTestHelper private constructor() {
    companion object {
        private val OBJECT_MAPPER = createObjectMapper()
        private val VALIDATOR = Validation.buildDefaultValidatorFactory().validator

        @JvmStatic
        fun createObjectMapper(): JsonMapper =
            JsonMapper
                .builder()
                .addModule(TimeModuleFactory.createTimeModule())
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
                .build()

        @JvmStatic
        fun serialize(dataObject: Any): ByteArray? {
            try {
                return OBJECT_MAPPER.writeValueAsBytes(dataObject)
            } catch (e: JacksonException) {
                throw RuntimeException(e)
            }
        }

        @JvmStatic
        fun serializeToString(dataObject: Any): String {
            try {
                return OBJECT_MAPPER.writeValueAsString(dataObject)
            } catch (e: JacksonException) {
                throw RuntimeException(e)
            }
        }

        @JvmStatic
        fun <T> deserialize(
            json: ByteArray,
            klass: Class<T>,
        ): T = OBJECT_MAPPER.readValue(json, klass)

        @JvmStatic
        fun <T> deserialize(
            json: String,
            klass: Class<T>,
        ): T = deserializeChecked(json, klass)

        @JvmStatic
        fun <T> deserializeChecked(
            json: String,
            klass: Class<T>,
        ): T = OBJECT_MAPPER.readValue(json, klass)

        @JvmStatic
        fun <T> validate(original: T): Set<ConstraintViolation<T>> = VALIDATOR.validate(original)

        @JvmStatic
        fun <T> deserializeAndValidate(
            json: String,
            klass: Class<T>,
        ): Set<ConstraintViolation<T>> {
            val dataObject = OBJECT_MAPPER.readValue(json, klass)
            return VALIDATOR.validate(dataObject)
        }

        @JvmStatic
        fun <T> deserializeAndValidate(
            json: ByteArray,
            klass: Class<T>,
        ): Set<ConstraintViolation<T>> {
            val dataObject = OBJECT_MAPPER.readValue(json, klass)
            return VALIDATOR.validate(dataObject)
        }

        @JvmStatic
        fun hasViolationWithMessage(expectedMessage: String): Matcher<ConstraintViolation<*>> {
            return object : BaseMatcher<ConstraintViolation<*>>() {
                override fun matches(item: Any): Boolean {
                    val violation = item as ConstraintViolation<*>
                    return violation.message == expectedMessage
                }

                override fun describeTo(description: Description) {
                    description
                        .appendText("getMessage() should equal ")
                        .appendValue(expectedMessage)
                }
            }
        }

        @JvmStatic
        @Throws(Exception::class)
        fun parse(jsonString: String): JsonNode = OBJECT_MAPPER.readTree(jsonString)
    }
}

package org.cloudfoundry.credhub.helpers

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.PropertyNamingStrategy.SNAKE_CASE
import org.cloudfoundry.credhub.util.TimeModuleFactory
import org.hamcrest.BaseMatcher
import org.hamcrest.Description
import org.hamcrest.Matcher
import java.io.IOException
import javax.validation.ConstraintViolation
import javax.validation.Validation

class JsonTestHelper private constructor() {

    companion object {
        private val OBJECT_MAPPER = createObjectMapper()
        private val VALIDATOR = Validation.buildDefaultValidatorFactory().validator

        @JvmStatic
        fun createObjectMapper(): ObjectMapper {
            return ObjectMapper()
                .registerModule(TimeModuleFactory.createTimeModule())
                .setPropertyNamingStrategy(SNAKE_CASE)
        }

        @JvmStatic
        fun serialize(dataObject: Any): kotlin.ByteArray? {
            try {
                return OBJECT_MAPPER.writeValueAsBytes(dataObject)
            } catch (e: JsonProcessingException) {
                throw RuntimeException(e)
            }
        }

        @JvmStatic
        fun serializeToString(dataObject: Any): String {
            try {
                return OBJECT_MAPPER.writeValueAsString(dataObject)
            } catch (e: JsonProcessingException) {
                throw RuntimeException(e)
            }
        }

        @JvmStatic
        fun <T> deserialize(json: kotlin.ByteArray, klass: Class<T>): T {
            try {
                return OBJECT_MAPPER.readValue(json, klass)
            } catch (e: IOException) {
                throw RuntimeException(e)
            }
        }

        @JvmStatic
        fun <T> deserialize(json: String, klass: Class<T>): T {
            try {
                return deserializeChecked<T>(json, klass)
            } catch (e: IOException) {
                throw RuntimeException(e)
            }
        }

        @JvmStatic
        @Throws(IOException::class)
        fun <T> deserializeChecked(json: String, klass: Class<T>): T {
            return OBJECT_MAPPER.readValue(json, klass)
        }

        @JvmStatic
        fun <T> validate(original: T): Set<ConstraintViolation<T>> {
            return VALIDATOR.validate(original)
        }

        @JvmStatic
        fun <T> deserializeAndValidate(json: String, klass: Class<T>): Set<ConstraintViolation<T>> {
            try {
                val dataObject = OBJECT_MAPPER.readValue(json, klass)
                return VALIDATOR.validate(dataObject)
            } catch (e: IOException) {
                throw RuntimeException(e)
            }
        }

        @JvmStatic
        fun <T> deserializeAndValidate(json: kotlin.ByteArray, klass: Class<T>): Set<ConstraintViolation<T>> {
            try {
                val dataObject = OBJECT_MAPPER.readValue(json, klass)
                return VALIDATOR.validate(dataObject)
            } catch (e: IOException) {
                throw RuntimeException(e)
            }
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
        fun parse(jsonString: String): JsonNode {
            return OBJECT_MAPPER.readTree(jsonString)
        }
    }
}

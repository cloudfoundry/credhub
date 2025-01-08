package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue
import com.fasterxml.jackson.databind.JsonNode
import org.cloudfoundry.credhub.ErrorMessages
import java.util.Objects
import javax.validation.constraints.NotNull

@JsonAutoDetect
class JsonCredentialValue
    @JsonCreator
    constructor(
        @field:NotNull(message = ErrorMessages.MISSING_VALUE)
        @get:JsonValue
        val value: JsonNode,
    ) : CredentialValue {
        override fun equals(other: Any?): Boolean {
            if (this === other) {
                return true
            }
            if (other == null || javaClass != other.javaClass) {
                return false
            }
            val that = other as JsonCredentialValue?
            return value == that!!.value
        }

        override fun hashCode(): Int = Objects.hash(value)
    }

package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue
import com.fasterxml.jackson.databind.JsonNode
import java.util.Objects
import javax.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages

@JsonAutoDetect
class JsonCredentialValue @JsonCreator
constructor(
    @field:NotNull(message = ErrorMessages.MISSING_VALUE)
    @get:JsonValue
    val value: JsonNode
) : CredentialValue {

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as JsonCredentialValue?
        return value == that!!.value
    }

    override fun hashCode(): Int {
        return Objects.hash(value)
    }
}

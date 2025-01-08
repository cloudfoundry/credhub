package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonValue
import org.cloudfoundry.credhub.ErrorMessages
import java.util.Objects
import javax.validation.constraints.NotEmpty

class StringCredentialValue(
    @field:NotEmpty(message = ErrorMessages.MISSING_VALUE)
    @get:JsonValue
    val stringCredential: String,
) : CredentialValue {
    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as StringCredentialValue?
        return stringCredential == that!!.stringCredential
    }

    override fun hashCode(): Int = Objects.hash(stringCredential)
}

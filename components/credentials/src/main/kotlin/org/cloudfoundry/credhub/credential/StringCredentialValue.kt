package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonValue
import java.util.Objects
import javax.validation.constraints.NotEmpty
import org.cloudfoundry.credhub.ErrorMessages

class StringCredentialValue(
    @field:NotEmpty(message = ErrorMessages.MISSING_VALUE)
    @get:JsonValue
    val stringCredential: String
) : CredentialValue {

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as StringCredentialValue?
        return stringCredential == that!!.stringCredential
    }

    override fun hashCode(): Int {
        return Objects.hash(stringCredential)
    }
}

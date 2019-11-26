package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import java.util.Objects
import javax.validation.Valid
import javax.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.StringCredentialValue

class ValueSetRequest : BaseCredentialSetRequest<StringCredentialValue?>() {

    @NotNull(message = ErrorMessages.MISSING_VALUE)
    @Valid
    @JsonProperty("value")
    var value: StringCredentialValue? = null

    override val generationParameters: GenerationParameters?
        get() = null

    override val credentialValue: StringCredentialValue?
        get() {
            return value
        }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as ValueSetRequest?
        return value == that!!.value
    }

    override fun hashCode(): Int {
        return Objects.hash(value)
    }
}

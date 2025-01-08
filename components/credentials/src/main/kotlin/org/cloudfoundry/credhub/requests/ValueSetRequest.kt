package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.StringCredentialValue
import java.util.Objects
import javax.validation.Valid
import javax.validation.constraints.NotNull

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

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as ValueSetRequest?
        return value == that!!.value
    }

    override fun hashCode(): Int = Objects.hash(value)
}

package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.Valid
import jakarta.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.JsonCredentialValue
import java.util.Objects

class JsonSetRequest : BaseCredentialSetRequest<JsonCredentialValue>() {
    @NotNull(message = ErrorMessages.MISSING_VALUE)
    @Valid
    @JsonProperty("value")
    var value: JsonCredentialValue? = null

    override val generationParameters: GenerationParameters?
        get() = null

    override val credentialValue: JsonCredentialValue
        get() {
            return this.value!!
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as JsonSetRequest?
        return value == that!!.value
    }

    override fun hashCode(): Int = Objects.hash(value)
}

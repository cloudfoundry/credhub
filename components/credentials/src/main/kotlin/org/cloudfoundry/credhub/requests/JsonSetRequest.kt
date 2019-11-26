package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import java.util.Objects
import javax.validation.Valid
import javax.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.JsonCredentialValue

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

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as JsonSetRequest?
        return value == that!!.value
    }

    override fun hashCode(): Int {
        return Objects.hash(value)
    }
}

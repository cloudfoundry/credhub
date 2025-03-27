package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.StringCredentialValue
import java.util.Objects
import jakarta.validation.Valid
import jakarta.validation.constraints.NotNull

class PasswordSetRequest : BaseCredentialSetRequest<StringCredentialValue?>() {
    @NotNull(message = ErrorMessages.MISSING_VALUE)
    @Valid
    @JsonProperty("value")
    var password: StringCredentialValue? = null

    @JsonIgnore
    override var generationParameters: StringGenerationParameters? = null

    override var credentialValue: StringCredentialValue? = null
        get() {
            return password
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as PasswordSetRequest?
        return password == that!!.password && generationParameters == that.generationParameters
    }

    override fun hashCode(): Int = Objects.hash(password, generationParameters)
}

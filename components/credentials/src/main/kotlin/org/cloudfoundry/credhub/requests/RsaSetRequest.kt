package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.RsaCredentialValue
import java.util.Objects
import javax.validation.Valid
import javax.validation.constraints.NotNull

class RsaSetRequest : BaseCredentialSetRequest<RsaCredentialValue?>() {
    @NotNull(message = ErrorMessages.MISSING_VALUE)
    @Valid
    @JsonProperty("value")
    var rsaKeyValue: RsaCredentialValue? = null

    override val generationParameters: GenerationParameters?
        get() = null

    override val credentialValue: RsaCredentialValue?
        get() {
            return rsaKeyValue
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as RsaSetRequest?
        return rsaKeyValue == that!!.rsaKeyValue
    }

    override fun hashCode(): Int = Objects.hash(rsaKeyValue)
}

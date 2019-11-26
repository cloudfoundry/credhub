package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import java.util.Objects
import javax.validation.Valid
import javax.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.RsaCredentialValue

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

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as RsaSetRequest?
        return rsaKeyValue == that!!.rsaKeyValue
    }

    override fun hashCode(): Int {
        return Objects.hash(rsaKeyValue)
    }
}

package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import java.util.Objects
import javax.validation.Valid
import javax.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.CertificateCredentialValue

class CertificateSetRequest : BaseCredentialSetRequest<CertificateCredentialValue>() {

    @NotNull(message = ErrorMessages.MISSING_VALUE)
    @Valid
    @JsonProperty("value")
    var certificateValue: CertificateCredentialValue? = null

    override val generationParameters: GenerationParameters?
        get() = null

    override val credentialValue: CertificateCredentialValue
        get() { return this.certificateValue!!
        }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as CertificateSetRequest?
        return certificateValue == that!!.certificateValue
    }

    override fun hashCode(): Int {
        return Objects.hash(certificateValue)
    }
}

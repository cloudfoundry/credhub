package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import jakarta.validation.Valid
import jakarta.validation.constraints.NotNull
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import java.util.Objects

class CertificateSetRequest : BaseCredentialSetRequest<CertificateCredentialValue>() {
    @NotNull(message = ErrorMessages.MISSING_VALUE)
    @Valid
    @JsonProperty("value")
    var certificateValue: CertificateCredentialValue? = null

    override val generationParameters: GenerationParameters?
        get() = null

    override val credentialValue: CertificateCredentialValue
        get() {
            return this.certificateValue!!
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as CertificateSetRequest?
        return certificateValue == that!!.certificateValue
    }

    override fun hashCode(): Int = Objects.hash(certificateValue)
}

package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException

class CertificateGenerateRequest : BaseCredentialGenerateRequest() {
    @JsonProperty("parameters")
    private var requestGenerationParameters: CertificateGenerationRequestParameters? = null

    @JsonIgnore
    private var certificateGenerationParameters: CertificateGenerationParameters? = null

    val generationRequestParameters: CertificateGenerationRequestParameters?
        get() {
            if (requestGenerationParameters == null) {
                requestGenerationParameters = CertificateGenerationRequestParameters()
            }
            return requestGenerationParameters
        }

    override val generationParameters: GenerationParameters?
        @JsonIgnore
        get() {
            if (certificateGenerationParameters == null && requestGenerationParameters == null) {
                throw ParameterizedValidationException(ErrorMessages.NO_CERTIFICATE_PARAMETERS)
            }

            if (certificateGenerationParameters == null) {
                certificateGenerationParameters = CertificateGenerationParameters(requestGenerationParameters!!)
            }
            return certificateGenerationParameters
        }

    fun setRequestGenerationParameters(requestGenerationParameters: CertificateGenerationRequestParameters) {
        this.requestGenerationParameters = requestGenerationParameters
    }

    override fun validate() {
        super.validate()
        generationRequestParameters?.validate()
    }

    fun setCertificateGenerationParameters(certificateGenerationParameters: CertificateGenerationParameters) {
        this.certificateGenerationParameters = certificateGenerationParameters
    }

    fun setAllowTransitionalParentToSign(allowTransitionalParentToSign: Boolean) {
        this.certificateGenerationParameters?.allowTransitionalParentToSign = allowTransitionalParentToSign
    }
}

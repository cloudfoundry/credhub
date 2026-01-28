package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import org.bouncycastle.asn1.x509.KeyUsage
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.CRL_SIGN
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.DATA_ENCIPHERMENT
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.DECIPHER_ONLY
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.DIGITAL_SIGNATURE
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.ENCIPHER_ONLY
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.KEY_AGREEMENT
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.KEY_CERT_SIGN
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.KEY_ENCIPHERMENT
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.NON_REPUDIATION

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

    fun setKeyLength(keyLength: Int) {
        this.certificateGenerationParameters?.keyLength = keyLength
        this.certificateGenerationParameters?.validate()
    }

    fun setDuration(duration: Int) {
        this.certificateGenerationParameters?.duration = duration
        this.certificateGenerationParameters?.validate()
    }

    fun setKeyUsage(keyUsage: Array<String>) {
        if (certificateGenerationParameters?.keyUsage == null) {
            var bitmask = 0
            for (usage in keyUsage) {
                bitmask =
                    when (usage) {
                        DIGITAL_SIGNATURE -> bitmask or KeyUsage.digitalSignature
                        NON_REPUDIATION -> bitmask or KeyUsage.nonRepudiation
                        KEY_ENCIPHERMENT -> bitmask or KeyUsage.keyEncipherment
                        DATA_ENCIPHERMENT -> bitmask or KeyUsage.dataEncipherment
                        KEY_AGREEMENT -> bitmask or KeyUsage.keyAgreement
                        KEY_CERT_SIGN -> bitmask or KeyUsage.keyCertSign
                        CRL_SIGN -> bitmask or KeyUsage.cRLSign
                        ENCIPHER_ONLY -> bitmask or KeyUsage.encipherOnly
                        DECIPHER_ONLY -> bitmask or KeyUsage.decipherOnly
                        else -> throw ParameterizedValidationException(ErrorMessages.INVALID_KEY_USAGE, usage)
                    }
            }
            certificateGenerationParameters?.keyUsage = KeyUsage(bitmask)
        }
    }
}

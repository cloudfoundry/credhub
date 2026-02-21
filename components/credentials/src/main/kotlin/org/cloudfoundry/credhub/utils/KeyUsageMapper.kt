package org.cloudfoundry.credhub.utils

import org.bouncycastle.asn1.x509.KeyUsage
import org.cloudfoundry.credhub.ErrorMessages
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

object KeyUsageMapper {
    /**
     * Converts an array of key usage strings into a BouncyCastle KeyUsage object.
     *
     * @param keyUsages Array of key usage string values
     * @return KeyUsage object with the appropriate bitmask
     * @throws ParameterizedValidationException if an invalid key usage string is provided
     */
    fun mapKeyUsage(keyUsages: Array<String>): KeyUsage {
        var bitmask = 0
        for (usage in keyUsages) {
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
        return KeyUsage(bitmask)
    }
}

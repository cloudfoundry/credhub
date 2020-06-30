package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT
import com.fasterxml.jackson.annotation.JsonProperty
import com.google.common.net.InetAddresses
import com.google.common.net.InternetDomainName
import org.apache.commons.lang3.StringUtils.isEmpty
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import java.util.Arrays
import java.util.regex.Pattern

@JsonInclude(NON_DEFAULT)
class CertificateGenerationRequestParameters {

    // Parameters used in RDN; at least one must be set
    val validKeyLengths = Arrays.asList(2048, 3072, 4096)
    var organization: String? = null
    var state: String? = null
    var country: String? = null
    var commonName: String? = null
    var organizationUnit: String? = null
    var locality: String? = null

    // Optional Certificate Parameters (not used in RDN)
    var keyLength = 2048
    var duration = 365
    private var selfSigned: Boolean = false
    @set:JsonProperty("ca")
    var caName: String? = null
    @set:JsonProperty("is_ca")
    var isCa: Boolean = false
    var alternativeNames: Array<String>? = null
        get(): Array<String>? {
            return if (field == null) null else field!!.clone()
        }
        set(alternativeNames) {
            field = alternativeNames?.clone()
        }
    var extendedKeyUsage: Array<String>? = null
        get(): Array<String>? {
            return if (field == null) null else field!!.clone()
        }
        set(extendedKeyUsage) {
            field = extendedKeyUsage?.clone()
        }
    var keyUsage: Array<String>? = null
        get(): Array<String>? {
            return if (field == null) null else field!!.clone()
        }

        set(keyUsage) {
            field = keyUsage?.clone()
        }
    private val validExtendedKeyUsages = Arrays
        .asList(SERVER_AUTH, CLIENT_AUTH, CODE_SIGNING, EMAIL_PROTECTION, TIMESTAMPING)

    private val validKeyUsages = Arrays
        .asList(
            DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT,
            KEY_AGREEMENT, KEY_CERT_SIGN, CRL_SIGN, ENCIPHER_ONLY, DECIPHER_ONLY
        )

    var isSelfSigned: Boolean
        get() {
            if (isCa && isEmpty(caName)) {
                selfSigned = true
            }

            return selfSigned
        }
        @JsonProperty("self_sign")
        set(selfSigned) {
            this.selfSigned = selfSigned
        }

    fun validate() {
        if (isEmpty(organization) &&
            isEmpty(state) &&
            isEmpty(locality) &&
            isEmpty(organizationUnit) &&
            isEmpty(commonName) &&
            isEmpty(country)
        ) {
            throw ParameterizedValidationException(ErrorMessages.MISSING_CERTIFICATE_PARAMETERS)
        } else if (isEmpty(caName) && !selfSigned && !isCa) {
            throw ParameterizedValidationException(ErrorMessages.MISSING_SIGNING_CA)
        } else if (!isEmpty(caName) && selfSigned) {
            throw ParameterizedValidationException(ErrorMessages.CA_AND_SELF_SIGN)
        }

        if (!validKeyLengths.contains(keyLength)) {
            throw ParameterizedValidationException(ErrorMessages.INVALID_KEY_LENGTH)
        }

        if (alternativeNames != null) {
            for (name in alternativeNames!!) {
                if (!InetAddresses.isInetAddress(name) && !(InternetDomainName.isValid(name) || DNS_WILDCARD_PATTERN.matcher(name).matches())) {
                    throw ParameterizedValidationException(ErrorMessages.INVALID_ALTERNATE_NAME)
                }
            }
        }

        if (extendedKeyUsage != null) {
            for (extendedKey in extendedKeyUsage!!) {
                if (!validExtendedKeyUsages.contains(extendedKey)) {
                    throw ParameterizedValidationException(
                        ErrorMessages.INVALID_EXTENDED_KEY_USAGE,
                        extendedKey
                    )
                }
            }
        }

        if (keyUsage != null) {
            for (keyUse in keyUsage!!) {
                if (!validKeyUsages.contains(keyUse)) {
                    throw ParameterizedValidationException(
                        ErrorMessages.INVALID_KEY_USAGE,
                        keyUse
                    )
                }
            }
        }

        if (duration < ONE_DAY || duration > TEN_YEARS) {
            throw ParameterizedValidationException(ErrorMessages.INVALID_DURATION)
        }

        validateParameterLength(commonName, "common name", 64)
        validateParameterLength(organization, "organization", 64)
        validateParameterLength(organizationUnit, "organization unit", 64)
        validateParameterLength(locality, "locality", 128)
        validateParameterLength(state, "state", 128)
        validateParameterLength(country, "country", 2)
        validateParameterLength(alternativeNames, "alternative name", 253)
    }

    companion object {
        const val SERVER_AUTH = "server_auth"
        const val CLIENT_AUTH = "client_auth"
        const val CODE_SIGNING = "code_signing"
        const val EMAIL_PROTECTION = "email_protection"
        const val TIMESTAMPING = "timestamping"
        const val DIGITAL_SIGNATURE = "digital_signature"
        const val NON_REPUDIATION = "non_repudiation"
        const val KEY_ENCIPHERMENT = "key_encipherment"
        const val DATA_ENCIPHERMENT = "data_encipherment"
        const val KEY_AGREEMENT = "key_agreement"
        const val KEY_CERT_SIGN = "key_cert_sign"
        const val CRL_SIGN = "crl_sign"
        const val ENCIPHER_ONLY = "encipher_only"
        const val DECIPHER_ONLY = "decipher_only"
        private val DNS_WILDCARD_PATTERN = Pattern
            .compile("^\\*?(?>(?:\\.[a-zA-Z0-9\\-]+))*$")

        private val TEN_YEARS = 3650
        private val ONE_DAY = 1

        private fun validateParameterLength(parameterArray: Array<String>?, parameterName: String, parameterLength: Int) {
            if (parameterArray != null) {
                for (parameter in parameterArray) {
                    validateParameterLength(parameter, parameterName, parameterLength)
                }
            }
        }

        private fun validateParameterLength(parameter: String?, parameterName: String, parameterLength: Int) {
            if (!isEmpty(parameter) && parameter!!.length > parameterLength) {
                throw ParameterizedValidationException(
                    ErrorMessages.Credential.INVALID_CERTIFICATE_PARAMETER, arrayOf(parameterName, parameterLength)
                )
            }
        }
    }
}

package org.cloudfoundry.credhub.domain

import com.google.common.collect.Lists.newArrayList
import com.google.common.net.InetAddresses
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings
import org.apache.commons.lang3.StringUtils.join
import org.apache.commons.lang3.StringUtils.prependIfMissing
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.GeneralNamesBuilder
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.CLIENT_AUTH
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.CODE_SIGNING
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.CRL_SIGN
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.DATA_ENCIPHERMENT
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.DECIPHER_ONLY
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.DIGITAL_SIGNATURE
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.EMAIL_PROTECTION
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.ENCIPHER_ONLY
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.KEY_AGREEMENT
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.KEY_CERT_SIGN
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.KEY_ENCIPHERMENT
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.NON_REPUDIATION
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.SERVER_AUTH
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.TIMESTAMPING
import org.cloudfoundry.credhub.requests.GenerationParameters
import org.cloudfoundry.credhub.utils.CertificateReader
import org.springframework.util.StringUtils
import java.util.Objects
import javax.security.auth.x500.X500Principal

class CertificateGenerationParameters : GenerationParameters {

    val keyLength: Int
    var duration: Int
    val isSelfSigned: Boolean
    val caName: String?
    val isCa: Boolean

    val x500Principal: X500Principal?
    val alternativeNames: GeneralNames?

    val extendedKeyUsage: ExtendedKeyUsage?

    val keyUsage: KeyUsage?

    var allowTransitionalParentToSign: Boolean = false

    constructor(generationParameters: CertificateGenerationRequestParameters) : super() {

        this.keyUsage = buildKeyUsage(generationParameters)
        this.x500Principal = buildDn(generationParameters)
        this.alternativeNames = buildAlternativeNames(generationParameters)
        this.extendedKeyUsage = buildExtendedKeyUsage(generationParameters)
        this.caName = if (generationParameters.caName != null) prependIfMissing(generationParameters.caName, "/") else null
        this.isSelfSigned = generationParameters.isSelfSigned
        this.duration = generationParameters.duration
        this.keyLength = generationParameters.keyLength
        this.isCa = generationParameters.isCa
    }

    constructor(certificateReader: CertificateReader, caName: String?) : super() {

        this.keyUsage = certificateReader.keyUsage
        this.x500Principal = certificateReader.subjectName
        this.alternativeNames = certificateReader.alternativeNames
        this.extendedKeyUsage = certificateReader.extendedKeyUsage
        this.caName = caName
        this.isSelfSigned = certificateReader.isSelfSigned
        this.duration = certificateReader.durationDays
        this.keyLength = certificateReader.keyLength
        this.isCa = certificateReader.isCa
    }

    override fun validate() {}

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as CertificateGenerationParameters?
        return keyLength == that!!.keyLength &&
            duration == that.duration &&
            isSelfSigned == that.isSelfSigned &&
            isCa == that.isCa &&
            (caName == that.caName || caName == null || that.caName == null) &&
            X500Name(that.x500Principal!!.name) == X500Name(this.x500Principal!!.name) &&
            alternativeNames == that.alternativeNames &&
            extendedKeyUsage == that.extendedKeyUsage &&
            keyUsage == that.keyUsage
    }

    fun equalsIgnoringDuration(other: CertificateGenerationParameters?): Boolean {
        return keyLength == other!!.keyLength &&
            isSelfSigned == other.isSelfSigned &&
            isCa == other.isCa &&
            (caName == other.caName || caName == null || other.caName == null) &&
            X500Name(other.x500Principal!!.name) == X500Name(this.x500Principal!!.name) &&
            alternativeNames == other.alternativeNames &&
            extendedKeyUsage == other.extendedKeyUsage &&
            keyUsage == other.keyUsage
    }

    override fun hashCode(): Int {
        return Objects.hash(keyLength, duration, isSelfSigned, caName, isCa, x500Principal, alternativeNames, extendedKeyUsage, keyUsage)
    }

    @SuppressFBWarnings
    private fun buildKeyUsage(keyUsageList: CertificateGenerationRequestParameters): KeyUsage? {
        if (keyUsageList.keyUsage == null) {
            return null
        }
        var bitmask = 0
        for (keyUsage in keyUsageList.keyUsage!!) {
            when (keyUsage) {
                DIGITAL_SIGNATURE -> bitmask = bitmask or KeyUsage.digitalSignature
                NON_REPUDIATION -> bitmask = bitmask or KeyUsage.nonRepudiation
                KEY_ENCIPHERMENT -> bitmask = bitmask or KeyUsage.keyEncipherment
                DATA_ENCIPHERMENT -> bitmask = bitmask or KeyUsage.dataEncipherment
                KEY_AGREEMENT -> bitmask = bitmask or KeyUsage.keyAgreement
                KEY_CERT_SIGN -> bitmask = bitmask or KeyUsage.keyCertSign
                CRL_SIGN -> bitmask = bitmask or KeyUsage.cRLSign
                ENCIPHER_ONLY -> bitmask = bitmask or KeyUsage.encipherOnly
                DECIPHER_ONLY -> bitmask = bitmask or KeyUsage.decipherOnly
                else -> throw ParameterizedValidationException(ErrorMessages.INVALID_KEY_USAGE, keyUsage)
            }
        }
        return KeyUsage(bitmask)
    }

    private fun buildDn(params: CertificateGenerationRequestParameters): X500Principal {
        if (this.x500Principal != null) {
            return this.x500Principal
        }

        val rdns = newArrayList<String>()

        if (!StringUtils.isEmpty(params.locality)) {
            rdns.add("L=" + params.locality!!)
        }
        if (!StringUtils.isEmpty(params.organization)) {
            rdns.add("O=" + params.organization!!)
        }
        if (!StringUtils.isEmpty(params.state)) {
            rdns.add("ST=" + params.state!!)
        }
        if (!StringUtils.isEmpty(params.country)) {
            rdns.add("C=" + params.country!!)
        }
        if (!StringUtils.isEmpty(params.organizationUnit)) {
            rdns.add("OU=" + params.organizationUnit!!)
        }
        if (!StringUtils.isEmpty(params.commonName)) {
            rdns.add("CN=" + params.commonName!!)
        }
        return X500Principal(join(rdns, ","))
    }

    private fun buildAlternativeNames(params: CertificateGenerationRequestParameters): GeneralNames? {
        val alternativeNamesList = params.alternativeNames ?: return null
        val builder = GeneralNamesBuilder()

        for (name in alternativeNamesList) {
            if (InetAddresses.isInetAddress(name)) {
                builder.addName(GeneralName(GeneralName.iPAddress, name))
            } else {
                builder.addName(GeneralName(GeneralName.dNSName, name))
            }
        }
        return builder.build()
    }

    private fun buildExtendedKeyUsage(params: CertificateGenerationRequestParameters): ExtendedKeyUsage? {
        val extendedKeyUsageList = params.extendedKeyUsage ?: return null
        val keyPurposeIds = arrayOfNulls<KeyPurposeId>(extendedKeyUsageList.size)
        for (i in extendedKeyUsageList.indices) {
            when (extendedKeyUsageList[i]) {
                SERVER_AUTH -> keyPurposeIds[i] = KeyPurposeId.id_kp_serverAuth
                CLIENT_AUTH -> keyPurposeIds[i] = KeyPurposeId.id_kp_clientAuth
                CODE_SIGNING -> keyPurposeIds[i] = KeyPurposeId.id_kp_codeSigning
                EMAIL_PROTECTION -> keyPurposeIds[i] = KeyPurposeId.id_kp_emailProtection
                TIMESTAMPING -> keyPurposeIds[i] = KeyPurposeId.id_kp_timeStamping
                else -> throw ParameterizedValidationException(ErrorMessages.INVALID_EXTENDED_KEY_USAGE, extendedKeyUsageList[i])
            }
        }
        return ExtendedKeyUsage(keyPurposeIds)
    }
}

package org.cloudfoundry.credhub.credential

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonInclude.Include
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.utils.CertificateReader
import org.cloudfoundry.credhub.utils.EmptyStringToNull
import org.cloudfoundry.credhub.validators.MutuallyExclusive
import org.cloudfoundry.credhub.validators.RequireAnyOf
import org.cloudfoundry.credhub.validators.RequireCertificateMatchesPrivateKey
import org.cloudfoundry.credhub.validators.RequireCertificateSignedByCA
import org.cloudfoundry.credhub.validators.RequireValidCA
import org.cloudfoundry.credhub.validators.RequireValidCertificate
import org.cloudfoundry.credhub.validators.ValidCertificateLength
import java.time.Instant
import java.util.Objects

@RequireAnyOf(message = ErrorMessages.MISSING_CERTIFICATE_CREDENTIALS, fields = ["ca", "certificate", "privateKey"])
@MutuallyExclusive(message = ErrorMessages.MIXED_CA_NAME_AND_CA, fields = ["ca", "caName"])
@ValidCertificateLength(message = ErrorMessages.INVALID_CERTIFICATE_LENGTH, fields = ["certificate", "ca"])
@RequireValidCertificate(message = ErrorMessages.INVALID_CERTIFICATE_VALUE, fields = ["certificate"])
@RequireCertificateSignedByCA(message = ErrorMessages.CERTIFICATE_WAS_NOT_SIGNED_BY_CA, fields = ["certificate","ca"])
@RequireCertificateMatchesPrivateKey(message = ErrorMessages.MISMATCHED_CERTIFICATE_AND_PRIVATE_KEY, fields = ["certificate", "privateKey"])
@RequireValidCA(message = ErrorMessages.INVALID_CA_VALUE, fields = ["certificate","ca"])
class CertificateCredentialValue : CredentialValue {

    @JsonDeserialize(using = EmptyStringToNull::class)
    var ca: String? = null
    @JsonDeserialize(using = EmptyStringToNull::class)
    var certificate: String? = null
    @JsonDeserialize(using = EmptyStringToNull::class)
    var privateKey: String? = null
    @JsonDeserialize(using = EmptyStringToNull::class)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    var caName: String? = null
        set(caName) {
            field = StringUtils.prependIfMissing(caName, "/")
        }
    @JsonIgnore
    var trustedCa: String? = null

    var transitional: Boolean = false
    var certificateAuthority: Boolean = false
    var selfSigned: Boolean = false
    @JsonInclude(Include.NON_NULL)
    var generated: Boolean? = null

    val expiryDate: Instant?
        get() = CertificateReader(certificate).notAfter

    @JsonIgnore
    var versionCreatedAt: Instant? = null

    @JsonInclude(Include.NON_NULL)
    var durationOverridden: Boolean? = null

    constructor() : super() {}

    constructor(
        ca: String?,
        certificate: String?,
        privateKey: String?,
        caName: String?,
        trustedCa: String?,
        certificateAuthority: Boolean,
        selfSigned: Boolean,
        generated: Boolean?,
        transitional: Boolean,
        durationOverridden: Boolean?
    ) : super() {
        this.ca = ca
        this.trustedCa = trustedCa
        this.certificate = certificate
        this.privateKey = privateKey
        this.transitional = transitional
        this.certificateAuthority = certificateAuthority
        this.selfSigned = selfSigned
        this.generated = generated
        this.caName = caName
        this.durationOverridden = durationOverridden
    }

    constructor(
        ca: String?,
        certificate: String?,
        privateKey: String?,
        caName: String?,
        certificateAuthority: Boolean,
        selfSigned: Boolean,
        generated: Boolean?,
        transitional: Boolean
    ) : this(
        ca,
        certificate,
        privateKey,
        caName,
        null,
        certificateAuthority,
        selfSigned,
        generated,
        transitional,
        null
    ) {
    }

    // used to create objects whose created at times can be compared
    constructor(
        certificate: String?,
        privateKey: String?,
        certificateAuthority: Boolean,
        selfSigned: Boolean,
        generated: Boolean?,
        transitional: Boolean,
        versionCreatedAt: Instant?
    ) : this(
        null,
        certificate,
        privateKey,
        null,
        null,
        certificateAuthority,
        selfSigned,
        generated,
        transitional,
        null
    ) {
        this.versionCreatedAt = versionCreatedAt
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as CertificateCredentialValue?
        return transitional == that!!.transitional &&
            certificateAuthority == that.certificateAuthority &&
            selfSigned == that.selfSigned &&
            ca == that.ca &&
            certificate == that.certificate &&
            privateKey == that.privateKey &&
            this.caName == that.caName
    }

    override fun hashCode(): Int {
        return Objects.hash(ca, certificate, privateKey, this.caName, transitional, certificateAuthority, selfSigned)
    }
}

package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonInclude
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import java.time.Instant
import java.util.Objects

class CertificateView : CredentialView {
    @JsonIgnore
    private var concatenateCas = false
    private var version: CertificateCredentialVersion? = null
    var expiryDate: Instant? = null
        private set
    var certificateAuthority = false
        private set
    var selfSigned = false
        private set
    @JsonInclude(JsonInclude.Include.NON_NULL)
    var generated: Boolean? = null
        private set

    internal constructor() : super() /* Jackson */ {}
    constructor(version: CertificateCredentialVersion) : super(
        version.versionCreatedAt,
        version.uuid,
        version.name,
        version.getCredentialType(),
        version.metadata,
        null
    ) {
        this.version = version
        expiryDate = version.expiryDate
        certificateAuthority = version.isCertificateAuthority
        selfSigned = version.isSelfSigned
        generated = version.generated
        concatenateCas = false
    }

    constructor(version: CertificateCredentialVersion, concatenateCas: Boolean) : super(
        version.versionCreatedAt,
        version.uuid,
        version.name,
        version.getCredentialType(),
        version.metadata,
        null
    ) {
        this.version = version
        expiryDate = version.expiryDate
        certificateAuthority = version.isCertificateAuthority
        selfSigned = version.isSelfSigned
        generated = version.generated
        this.concatenateCas = concatenateCas
    }

    override var value: CredentialValue?
        get() = CertificateValueView(version!!, concatenateCas)
        set(value) {
            super.value = value
        }

    val isTransitional: Boolean
        get() = version!!.isVersionTransitional

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        if (!super.equals(other)) {
            return false
        }
        val that = other as CertificateView
        return certificateAuthority == that.certificateAuthority && selfSigned == that.selfSigned &&
            generated == that.generated &&
            version == that.version &&
            expiryDate == that.expiryDate
    }

    override fun hashCode(): Int {
        return Objects.hash(super.hashCode(), version, expiryDate, certificateAuthority, selfSigned, generated)
    }
}

package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonInclude
import java.time.Instant
import java.util.Objects
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion

class CertificateView : CredentialView {
    @JsonIgnore
    private var concatenateCas = false
    private var version: CertificateCredentialVersion? = null
    var expiryDate: Instant? = null
        private set
    var isCertificateAuthority = false
        private set
    var isSelfSigned = false
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
        isCertificateAuthority = version.isCertificateAuthority
        isSelfSigned = version.isSelfSigned
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
        isCertificateAuthority = version.isCertificateAuthority
        isSelfSigned = version.isSelfSigned
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

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        if (!super.equals(o)) {
            return false
        }
        val that = o as CertificateView
        return isCertificateAuthority == that.isCertificateAuthority && isSelfSigned == that.isSelfSigned &&
            generated == that.generated &&
            version == that.version &&
            expiryDate == that.expiryDate
    }

    override fun hashCode(): Int {
        return Objects.hash(super.hashCode(), version, expiryDate, isCertificateAuthority, isSelfSigned, generated)
    }
}

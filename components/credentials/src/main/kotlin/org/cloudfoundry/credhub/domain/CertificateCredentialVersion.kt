package org.cloudfoundry.credhub.domain

import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.requests.GenerationParameters
import org.cloudfoundry.credhub.utils.CertificateReader
import java.time.Instant
import java.util.Objects

class CertificateCredentialVersion(delegate: CertificateCredentialVersionData) : CredentialVersion(delegate) {
    lateinit var parsedCertificate: CertificateReader
        private set

    var ca: String?
        get() = (delegate as CertificateCredentialVersionData).ca
        set(ca) {
            (delegate as CertificateCredentialVersionData).ca = ca
        }

    var certificate: String?
        get() = (delegate as CertificateCredentialVersionData).certificate
        set(certificate) {
            (delegate as CertificateCredentialVersionData).certificate = certificate
            if (StringUtils.isNotEmpty((delegate as CertificateCredentialVersionData).certificate)) {
                parsedCertificate = CertificateReader(certificate)
            }
        }

    var trustedCa: String?
        get() = (delegate as CertificateCredentialVersionData).trustedCa
        set(trustedCa) {
            (delegate as CertificateCredentialVersionData).trustedCa = trustedCa
        }

    var privateKey: String?
        get() = super.getValue() as String?
        set(privateKey) {
            if (privateKey != null) {
                super.setValue(privateKey)
            }
        }

    var caName: String?
        get() = (delegate as CertificateCredentialVersionData).caName
        set(caName) {
            (delegate as CertificateCredentialVersionData).caName = caName
        }

    var expiryDate: Instant?
        get() = (delegate as CertificateCredentialVersionData).expiryDate
        set(expiryDate) {
            (delegate as CertificateCredentialVersionData).expiryDate = expiryDate
        }

    val isVersionTransitional: Boolean
        get() = (delegate as CertificateCredentialVersionData).isTransitional()

    var isSelfSigned: Boolean
        get() = (delegate as CertificateCredentialVersionData).isSelfSigned
        set(isSelfSigned) {
            (delegate as CertificateCredentialVersionData).isSelfSigned = isSelfSigned
        }

    var isCertificateAuthority: Boolean
        get() = (delegate as CertificateCredentialVersionData).isCertificateAuthority
        set(certificateAuthority) {
            (delegate as CertificateCredentialVersionData).isCertificateAuthority = certificateAuthority
        }

    var generated: Boolean?
        get() = (delegate as CertificateCredentialVersionData).generated
        set(generated) {
            (delegate as CertificateCredentialVersionData).generated = generated
        }

    init {
        this.certificate = delegate.certificate
    }

    constructor(name: String) : this(CertificateCredentialVersionData(name)) {}

    constructor(certificate: CertificateCredentialValue, credentialName: String, encryptor: Encryptor) : this(credentialName) {
        this.setEncryptor(encryptor)
        this.ca = certificate.ca
        this.privateKey = certificate.privateKey
        this.caName = certificate.caName
        this.certificate = certificate.certificate
        this.setTransitional(certificate.transitional)
        this.expiryDate = certificate.expiryDate
        this.isCertificateAuthority = certificate.certificateAuthority
        this.trustedCa = certificate.trustedCa
        this.isSelfSigned = certificate.selfSigned
        this.generated = certificate.generated
    }

    override fun getCredentialType(): String {
        return delegate.credentialType
    }

    override fun rotate() {
        val decryptedPrivateKey = this.privateKey
        this.privateKey = decryptedPrivateKey
    }

    override fun matchesGenerationParameters(generationParameters: GenerationParameters?): Boolean {
        if (generationParameters == null) {
            return true
        }

        val parameters = generationParameters as CertificateGenerationParameters?
        val existingGenerationParameters = CertificateGenerationParameters(parsedCertificate, caName)
        return existingGenerationParameters == parameters
    }

    fun setTransitional(transitional: Boolean) {
        (delegate as CertificateCredentialVersionData).transitional = transitional
    }

    override fun getGenerationParameters(): GenerationParameters? {
        return null
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as CertificateCredentialVersion?
        return (
            delegate == that!!.delegate &&
                name == that.name &&
                uuid == that.uuid &&
                versionCreatedAt == that.versionCreatedAt
            )
    }

    override fun hashCode(): Int {
        return Objects.hash(delegate)
    }
}

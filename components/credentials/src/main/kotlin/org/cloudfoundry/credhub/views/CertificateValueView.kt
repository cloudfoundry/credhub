package org.cloudfoundry.credhub.views

import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion

class CertificateValueView(value: CertificateCredentialVersion, concatenateCas: Boolean) : CredentialValue {
    val ca: String?
    val certificate: String?
    val privateKey: String?

    init {
        if (!concatenateCas || value.trustedCa == null || value.trustedCa!!.isEmpty()) {
            ca = value.ca
        } else {
            val trustedCa = value.trustedCa
            val ca = value.ca
            this.ca = ca!!.trim { it <= ' ' } + "\n" + trustedCa!!.trim { it <= ' ' } + "\n"
        }
        certificate = value.certificate
        privateKey = value.privateKey
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CertificateValueView

        if (ca != other.ca) return false
        if (certificate != other.certificate) return false
        if (privateKey != other.privateKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ca?.hashCode() ?: 0
        result = 31 * result + (certificate?.hashCode() ?: 0)
        result = 31 * result + (privateKey?.hashCode() ?: 0)
        return result
    }
}

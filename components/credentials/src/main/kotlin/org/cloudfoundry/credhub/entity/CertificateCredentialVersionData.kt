package org.cloudfoundry.credhub.entity

import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.entities.CredentialVersionData
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData.Companion.CREDENTIAL_DATABASE_TYPE
import java.time.Instant
import java.util.Objects
import javax.persistence.Column
import javax.persistence.DiscriminatorValue
import javax.persistence.Entity
import javax.persistence.PrimaryKeyJoinColumn
import javax.persistence.SecondaryTable

@Entity
@DiscriminatorValue(CREDENTIAL_DATABASE_TYPE)
@SecondaryTable(name = CertificateCredentialVersionData.TABLE_NAME, pkJoinColumns = [PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")])
class CertificateCredentialVersionData : CredentialVersionData<CertificateCredentialVersionData> {

    @Column(table = CertificateCredentialVersionData.TABLE_NAME, length = 7000)
    var ca: String? = null

    @Column(table = CertificateCredentialVersionData.TABLE_NAME, length = 7000)
    var certificate: String? = null

    @Column(table = CertificateCredentialVersionData.TABLE_NAME)
    var caName: String? = null
        set(caName) {
            field = if (!StringUtils.isEmpty(caName)) StringUtils.prependIfMissing(caName, "/") else caName
        }

    @Column(table = CertificateCredentialVersionData.TABLE_NAME)
    var transitional: Boolean = false

    @Column(table = CertificateCredentialVersionData.TABLE_NAME)
    var expiryDate: Instant? = null

    @Column(table = CertificateCredentialVersionData.TABLE_NAME)
    private var certificateAuthority: Boolean? = null

    @Column(table = CertificateCredentialVersionData.TABLE_NAME)
    private var selfSigned: Boolean? = null

    @Column(table = CertificateCredentialVersionData.TABLE_NAME, name = "certificate_generated")
    var generated: Boolean? = null

    @Column(table = CertificateCredentialVersionData.TABLE_NAME, length = 7000, columnDefinition = "TEXT")
    var trustedCa: String? = null

    val name: String?
        get() = super.credential!!.name

    override val credentialType: String
        get() = CREDENTIAL_TYPE

    var isSelfSigned: Boolean
        get() = if (selfSigned == null) {
            false
        } else selfSigned!!
        set(selfSigned) {
            this.selfSigned = selfSigned
        }

    var isCertificateAuthority: Boolean
        get() = if (certificateAuthority == null) {
            false
        } else certificateAuthority!!
        set(certificateAuthority) {
            this.certificateAuthority = certificateAuthority
        }

    // Needed for hibernate
    constructor() : super() {}

    constructor(name: String) : super(name) {}

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null || javaClass != other.javaClass) {
            return false
        }
        val that = other as CertificateCredentialVersionData?
        return isTransitional() == that!!.isTransitional() &&
            certificateAuthority == that.certificateAuthority &&
            selfSigned == that.selfSigned &&
            ca == that.ca &&
            certificate == that.certificate &&
            this.caName == that.caName &&
            expiryDate == that.expiryDate
    }

    fun isTransitional(): Boolean {
        return this.transitional
    }

    override fun hashCode(): Int {
        return Objects.hash(ca, certificate, this.caName, isTransitional(), expiryDate, certificateAuthority, selfSigned)
    }

    override fun toString(): String {
        return "CertificateCredentialVersionData{" +
            "ca='" + ca + '\''.toString() +
            ", certificate='" + certificate + '\''.toString() +
            ", caName='" + this.caName + '\''.toString() +
            ", transitional=" + isTransitional() +
            ", expiryDate=" + expiryDate +
            ", certificateAuthority=" + certificateAuthority +
            ", selfSigned=" + selfSigned +
            '}'.toString()
    }

    companion object {
        const val CREDENTIAL_DATABASE_TYPE = "cert"
        const val CREDENTIAL_TYPE = "certificate"
        const val TABLE_NAME = "certificate_credential"
    }
}

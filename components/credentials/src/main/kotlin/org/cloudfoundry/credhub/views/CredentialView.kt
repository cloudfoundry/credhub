package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonProperty
import java.time.Instant
import java.util.Objects
import java.util.UUID
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.domain.JsonCredentialVersion
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion
import org.cloudfoundry.credhub.domain.RsaCredentialVersion
import org.cloudfoundry.credhub.domain.SshCredentialVersion
import org.cloudfoundry.credhub.domain.UserCredentialVersion
import org.cloudfoundry.credhub.domain.ValueCredentialVersion

open class CredentialView {
    @get:JsonProperty("version_created_at")
    var versionCreatedAt: Instant? = null
        private set
    private var uuid: UUID? = null
    @get:JsonProperty("name")
    var name: String? = null
        private set
    @get:JsonProperty
    var type: String? = null
        private set
    @get:JsonProperty("value")
    open var value: CredentialValue? = null

    constructor() : super() /* Jackson */ {}
    constructor(
        versionCreatedAt: Instant?,
        uuid: UUID?,
        name: String?,
        type: String?,
        value: CredentialValue?
    ) : super() {
        this.versionCreatedAt = versionCreatedAt
        this.uuid = uuid
        this.name = name
        this.type = type
        this.value = value
    }

    @JsonProperty("id")
    fun getUuid(): String {
        return if (uuid == null) "" else uuid.toString()
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val that = o as CredentialView
        return versionCreatedAt == that.versionCreatedAt &&
            uuid == that.uuid &&
            name == that.name &&
            type == that.type &&
            value == that.value
    }

    override fun hashCode(): Int {
        return Objects.hash(versionCreatedAt, uuid, name, type, value)
    }

    companion object {
        @JvmOverloads
        @JvmStatic
        fun fromEntity(credentialVersion: CredentialVersion?, concatenateCas: Boolean = false): CredentialView {
            return when (credentialVersion) {
                is ValueCredentialVersion -> {
                    ValueView((credentialVersion as ValueCredentialVersion?)!!)
                }
                is PasswordCredentialVersion -> {
                    PasswordView(credentialVersion)
                }
                is CertificateCredentialVersion -> {
                    CertificateView(credentialVersion, concatenateCas)
                }
                is SshCredentialVersion -> {
                    SshView(credentialVersion)
                }
                is RsaCredentialVersion -> {
                    RsaView(credentialVersion)
                }
                is JsonCredentialVersion -> {
                    JsonView((credentialVersion as JsonCredentialVersion?)!!)
                }
                is UserCredentialVersion -> {
                    UserView(credentialVersion)
                }
                else -> {
                    throw IllegalArgumentException()
                }
            }
        }
    }
}

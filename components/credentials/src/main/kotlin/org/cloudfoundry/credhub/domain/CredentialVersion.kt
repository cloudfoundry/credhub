package org.cloudfoundry.credhub.domain

import com.fasterxml.jackson.databind.JsonNode
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings
import org.cloudfoundry.credhub.audit.AuditableCredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.entity.CredentialVersionData
import org.cloudfoundry.credhub.requests.GenerationParameters
import org.cloudfoundry.credhub.services.CredentialVersionDataService
import java.time.Instant
import java.util.UUID

abstract class CredentialVersion(protected var delegate: CredentialVersionData<*>) : AuditableCredentialVersion {
    private lateinit var encryptor: Encryptor

    override var uuid: UUID?
        get() = delegate.uuid
        set(uuid) {
            delegate.uuid = uuid
        }
    val name: String?
        @SuppressFBWarnings
        get() = delegate.credential!!.name

    var versionCreatedAt: Instant
        get() = delegate.versionCreatedAt
        set(versionCreatedAt) {
            delegate.versionCreatedAt = versionCreatedAt
        }

    var credential: Credential?
        get() = delegate.credential
        set(credential) {
            this.delegate.credential = credential
        }

    var metadata: JsonNode?
        get() = delegate.metadata
        set(metadata) {
            this.delegate.metadata = metadata
        }

    abstract fun rotate()

    protected fun getEncryptor(): Encryptor {
        return this.encryptor
    }

    fun setEncryptor(encryptor: Encryptor) {
        this.encryptor = encryptor
    }

    open fun getValue(): Any? {
        return encryptor.decrypt(delegate.getEncryptedValueData())
    }

    open fun setValue(value: String) {
        val encryption = encryptor.encrypt(value)
        delegate.setEncryptedValueData(encryption)
    }

    fun <Z : CredentialVersion> save(credentialVersionDataService: CredentialVersionDataService): Z {
        return credentialVersionDataService.save(delegate) as Z
    }

    fun copyNameReferenceFrom(credentialVersion: CredentialVersion) {
        this.delegate.credential = credentialVersion.delegate.credential
    }

    fun createName(name: String) {
        delegate.credential = Credential(name)
    }

    abstract fun getCredentialType(): String

    abstract fun getGenerationParameters(): GenerationParameters?

    abstract fun matchesGenerationParameters(generationParameters: GenerationParameters?): Boolean
}

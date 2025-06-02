package org.cloudfoundry.credhub.entity

import com.fasterxml.jackson.databind.JsonNode
import jakarta.persistence.CascadeType
import jakarta.persistence.Column
import jakarta.persistence.Convert
import jakarta.persistence.DiscriminatorColumn
import jakarta.persistence.DiscriminatorType
import jakarta.persistence.Entity
import jakarta.persistence.EntityListeners
import jakarta.persistence.GeneratedValue
import jakarta.persistence.Id
import jakarta.persistence.Inheritance
import jakarta.persistence.InheritanceType
import jakarta.persistence.JoinColumn
import jakarta.persistence.ManyToOne
import jakarta.persistence.OneToOne
import jakarta.persistence.Table
import org.cloudfoundry.credhub.constants.UuidConstants
import org.cloudfoundry.credhub.entities.EncryptedValue
import org.cloudfoundry.credhub.util.InstantMillisecondsConverter
import org.cloudfoundry.credhub.utils.JsonNodeConverter
import org.hibernate.annotations.NotFound
import org.hibernate.annotations.NotFoundAction
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.jpa.domain.support.AuditingEntityListener
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "credential_version")
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@EntityListeners(AuditingEntityListener::class)
@DiscriminatorColumn(name = "type", discriminatorType = DiscriminatorType.STRING)
abstract class CredentialVersionData<Z : CredentialVersionData<Z>>(
    credential: Credential?,
) {
    // Use VARBINARY to make all 3 DB types happy.
    // H2 doesn't distinguish between "binary" and "varbinary" - see
    // https://hibernate.atlassian.net/browse/HHH-9835 and
    // https://github.com/h2database/h2database/issues/345
    @Id
    @Column(length = UuidConstants.UUID_BYTES, columnDefinition = "VARBINARY")
    @GeneratedValue(generator = "uuid2")
    open var uuid: UUID? = null

    @OneToOne(cascade = [CascadeType.ALL])
    @NotFound(action = NotFoundAction.IGNORE)
    @JoinColumn(name = "encrypted_value_uuid")
    open var encryptedCredentialValue: EncryptedValue? = null

    @Convert(converter = InstantMillisecondsConverter::class)
    @Column(nullable = false, columnDefinition = "BIGINT NOT NULL")
    @CreatedDate
    open lateinit var versionCreatedAt: Instant

    @ManyToOne
    @JoinColumn(name = "credential_uuid", nullable = false)
    open var credential: Credential? = credential

    // this is mapped with updatable and insertable false since it's managed by the DiscriminatorColumn annotation
    // surfacing property here lets us use it in JPA queries
    @Column(name = "type", insertable = false, updatable = false)
    private val type: String? = null

    @Convert(converter = JsonNodeConverter::class)
    @Column(name = "metadata")
    open var metadata: JsonNode? = null

    val nonce: ByteArray?
        get() = if (encryptedCredentialValue != null) this.encryptedCredentialValue!!.nonce else null

    abstract val credentialType: String

    val encryptionKeyUuid: UUID?
        get() = if (encryptedCredentialValue != null) encryptedCredentialValue!!.encryptionKeyUuid else null

    fun getEncryptedValueData(): EncryptedValue? = this.encryptedCredentialValue

    fun setEncryptedValueData(encryptedValue: EncryptedValue?) {
        this.encryptedCredentialValue = encryptedValue
    }

    constructor(name: String?) : this(Credential(name))

    constructor() : this(credential = null)
}

package org.cloudfoundry.credhub.entity

import jakarta.persistence.CascadeType
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.FetchType
import jakarta.persistence.GeneratedValue
import jakarta.persistence.Id
import jakarta.persistence.OneToMany
import jakarta.persistence.Table
import org.apache.commons.codec.digest.DigestUtils
import org.cloudfoundry.credhub.audit.AuditableCredential
import org.cloudfoundry.credhub.constants.UuidConstants.Companion.UUID_BYTES
import org.hibernate.annotations.GenericGenerator
import java.util.UUID

@Entity
@Table(name = "credential")
class Credential : AuditableCredential {
    @Id
    @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    override var uuid: UUID? = null

    @OneToMany(
        cascade = [CascadeType.REMOVE],
        mappedBy = "credential",
        fetch = FetchType.LAZY,
    )
    var credentialVersions: MutableList<CredentialVersionData<*>> =
        mutableListOf()

    @Column(nullable = false)
    override var name: String? = null
        set(name) {
            field = name
            if (name != null) {
                checksum = DigestUtils.sha256Hex(name)
            }
        }

    @Column(name = "name_lowercase", nullable = false, insertable = false)
    var nameLowercase: String? = null

    @Column(unique = true, nullable = false)
    var checksum: String? = null

    // Needed for hibernate
    internal constructor() : this(null) {}

    constructor(name: String?) {
        this.name = name
    }
}

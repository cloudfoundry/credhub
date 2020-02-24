package org.cloudfoundry.credhub.entity

import java.util.UUID
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.Id
import javax.persistence.Table
import org.apache.commons.codec.digest.DigestUtils
import org.cloudfoundry.credhub.audit.AuditableCredential
import org.cloudfoundry.credhub.constants.UuidConstants.Companion.UUID_BYTES
import org.hibernate.annotations.GenericGenerator

@Entity
@Table(name = "credential")
class Credential : AuditableCredential {

    @Id
    @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    override var uuid: UUID? = null

    @Column(nullable = false)
    override var name: String? = null
        set(name) {
            field = name
            if (name != null) {
                checksum = DigestUtils.sha256Hex(name)
            }
        }

    @Column(unique = true, nullable = false)
    var checksum: String? = null

    // Needed for hibernate
    internal constructor() : this(null) {}

    constructor(name: String?) {
        this.name = name
    }
}

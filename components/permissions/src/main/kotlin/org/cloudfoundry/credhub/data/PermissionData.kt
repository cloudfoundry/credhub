package org.cloudfoundry.credhub.data

import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.PermissionOperation.DELETE
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.READ_ACL
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.PermissionOperation.WRITE_ACL
import org.cloudfoundry.credhub.audit.AuditablePermissionData
import org.cloudfoundry.credhub.constants.UuidConstants
import org.hibernate.annotations.GenericGenerator
import java.util.UUID
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.Id
import javax.persistence.Table

@Entity
@Table(name = "permission")
class PermissionData(
    @field:Column(nullable = false)
    override var path: String?,
    @field:Column(nullable = false)
    var actor: String?,
) : AuditablePermissionData {
    @Id
    @Column(length = UuidConstants.UUID_BYTES, columnDefinition = "VARBINARY")
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    override var uuid: UUID? = null

    @Column(name = "read_permission", nullable = false)
    private var readPermission = DEFAULT_DENY

    @Column(name = "write_permission", nullable = false)
    private var writePermission = DEFAULT_DENY

    @Column(name = "delete_permission", nullable = false)
    private var deletePermission = DEFAULT_DENY

    @Column(name = "read_acl_permission", nullable = false)
    private var readAclPermission = DEFAULT_DENY

    @Column(name = "write_acl_permission", nullable = false)
    private var writeAclPermission = DEFAULT_DENY

    constructor() : this(null, null, ArrayList<PermissionOperation>()) {}

    constructor(
        path: String?,
        actor: String?,
        operations: MutableList<PermissionOperation>?,
    ) : this(path, actor) {
        enableOperations(operations)
    }

    fun hasReadPermission(): Boolean = readPermission

    fun hasWritePermission(): Boolean = writePermission

    fun hasDeletePermission(): Boolean = deletePermission

    fun hasWriteAclPermission(): Boolean = writeAclPermission

    fun hasReadAclPermission(): Boolean = readAclPermission

    fun hasPermission(requiredPermission: PermissionOperation): Boolean {
        when (requiredPermission) {
            READ -> return hasReadPermission()
            WRITE -> return hasWritePermission()
            DELETE -> return hasDeletePermission()
            READ_ACL -> return hasReadAclPermission()
            WRITE_ACL -> return hasWriteAclPermission()
            else -> return false
        }
    }

    fun enableOperations(operations: List<PermissionOperation>?) {
        if (operations != null) {
            for (operation in operations) {
                enableOperation(operation)
            }
        }
    }

    fun generateAccessControlOperations(): List<PermissionOperation> {
        val operations = ArrayList<PermissionOperation>()

        if (hasReadPermission()) {
            operations.add(READ)
        }
        if (hasWritePermission()) {
            operations.add(WRITE)
        }
        if (hasDeletePermission()) {
            operations.add(DELETE)
        }
        if (hasReadAclPermission()) {
            operations.add(READ_ACL)
        }
        if (hasWriteAclPermission()) {
            operations.add(WRITE_ACL)
        }
        return operations
    }

    private fun enableOperation(operation: PermissionOperation) {
        when (operation) {
            READ -> readPermission = true
            WRITE -> writePermission = true
            DELETE -> deletePermission = true
            WRITE_ACL -> writeAclPermission = true
            READ_ACL -> readAclPermission = true
            else -> throw RuntimeException()
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as PermissionData?
        return readPermission == that!!.readPermission &&
            writePermission == that.writePermission &&
            deletePermission == that.deletePermission &&
            readAclPermission == that.readAclPermission &&
            writeAclPermission == that.writeAclPermission &&
            uuid == that.uuid &&
            path == that.path &&
            actor == that.actor
    }

    companion object {
        private val DEFAULT_DENY = false
    }
}

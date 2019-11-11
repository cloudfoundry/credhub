package org.cloudfoundry.credhub.services

import java.util.UUID
import org.cloudfoundry.credhub.PermissionOperation

class AlwaysTruePermissionCheckingService : PermissionCheckingService {
    override fun findAllPathsByActor(actor: String): Set<String> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun hasPermission(user: String, permissionGuid: UUID, permission: PermissionOperation): Boolean {
        return true
    }

    override fun hasPermissions(user: String, path: String, permissions: List<PermissionOperation>): Boolean {
        return true
    }

    override fun userAllowedToOperateOnActor(actor: String?): Boolean {
        return true
    }

    override fun userAllowedToOperateOnActor(guid: UUID): Boolean {
        return true
    }

    override fun hasPermission(user: String, credentialName: String, permission: PermissionOperation): Boolean {
        return true
    }
}

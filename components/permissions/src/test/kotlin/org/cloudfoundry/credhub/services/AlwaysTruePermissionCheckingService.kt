package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.PermissionOperation
import java.util.UUID

class AlwaysTruePermissionCheckingService : PermissionCheckingService {
    override fun findAllPathsByActor(actor: String): Set<String> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun hasPermission(
        user: String,
        permissionGuid: UUID,
        permission: PermissionOperation,
    ): Boolean = true

    override fun hasPermissions(
        user: String,
        path: String,
        permissions: List<PermissionOperation>,
    ): Boolean = true

    override fun userAllowedToOperateOnActor(actor: String?): Boolean = true

    override fun userAllowedToOperateOnActor(guid: UUID): Boolean = true

    override fun hasPermission(
        user: String,
        credentialName: String,
        permission: PermissionOperation,
    ): Boolean = true
}

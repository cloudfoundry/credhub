package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.PermissionOperation
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class AlwaysTruePermissionCheckingService : PermissionCheckingService {
    override fun hasPermission(user: String, guid: UUID, permission: PermissionOperation): Boolean {
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

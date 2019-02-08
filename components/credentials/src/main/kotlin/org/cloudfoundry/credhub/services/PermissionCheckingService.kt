package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.PermissionOperation
import java.util.UUID

interface PermissionCheckingService {

    fun hasPermission(user: String, credentialName: String, permission: PermissionOperation): Boolean

    fun hasPermission(user: String, guid: UUID, permission: PermissionOperation): Boolean

    fun hasPermissions(user: String, path: String, permissions: List<PermissionOperation>): Boolean

    fun userAllowedToOperateOnActor(actor: String?): Boolean

    fun userAllowedToOperateOnActor(guid: UUID): Boolean
}

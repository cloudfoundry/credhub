package org.cloudfoundry.credhub.services

import java.util.UUID
import org.cloudfoundry.credhub.PermissionOperation

interface PermissionCheckingService {

    fun hasPermission(user: String, credentialName: String, permission: PermissionOperation): Boolean

    fun hasPermission(user: String, permissionGuid: UUID, permission: PermissionOperation): Boolean

    fun hasPermissions(user: String, path: String, permissions: List<PermissionOperation>): Boolean

    fun userAllowedToOperateOnActor(actor: String?): Boolean

    fun userAllowedToOperateOnActor(guid: UUID): Boolean

    fun findAllPathsByActor(actor: String): Set<String>
}

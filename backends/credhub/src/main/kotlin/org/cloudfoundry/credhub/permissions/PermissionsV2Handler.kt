package org.cloudfoundry.credhub.permissions

import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.views.PermissionsV2View
import java.util.UUID

interface PermissionsV2Handler {
    fun writePermissions(request: PermissionsV2Request): PermissionsV2View

    fun getPermissions(guid: UUID): PermissionsV2View

    fun putPermissions(guid: String, permissionsRequest: PermissionsV2Request): PermissionsV2View

    fun patchPermissions(guid: String, operations: List<PermissionOperation>): PermissionsV2View

    fun writeV2Permissions(permissionsRequest: PermissionsV2Request): PermissionsV2View

    fun deletePermissions(guid: String): PermissionsV2View

    fun findByPathAndActor(path: String, actor: String): PermissionsV2View
}

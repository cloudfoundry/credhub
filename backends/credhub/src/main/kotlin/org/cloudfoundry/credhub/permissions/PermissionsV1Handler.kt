package org.cloudfoundry.credhub.permissions

import org.cloudfoundry.credhub.requests.PermissionsRequest
import org.cloudfoundry.credhub.views.PermissionsView

interface PermissionsV1Handler {
    fun getPermissions(name: String): PermissionsView

    fun writePermissions(request: PermissionsRequest)

    fun deletePermissionEntry(credentialName: String, actor: String)
}

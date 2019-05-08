package org.cloudfoundry.credhub.controllers.v1.permissions

import org.cloudfoundry.credhub.permissions.PermissionsV1Handler
import org.cloudfoundry.credhub.requests.PermissionsRequest
import org.cloudfoundry.credhub.views.PermissionsView

class SpyPermissionsV1Handler : PermissionsV1Handler {

    lateinit var getPermissions__calledWith_name: String
    lateinit var getPermissions__returns_permissionsView: PermissionsView
    override fun getPermissions(name: String): PermissionsView {
        getPermissions__calledWith_name = name
        return getPermissions__returns_permissionsView
    }

    lateinit var writePermissions__calledWith_request: PermissionsRequest
    override fun writePermissions(request: PermissionsRequest) {
        writePermissions__calledWith_request = request
    }

    lateinit var deletePermissionEntry__calledWith_credentialName: String
    lateinit var deletePermissionEntry__calledWith_actor: String
    override fun deletePermissionEntry(credentialName: String, actor: String) {
        deletePermissionEntry__calledWith_credentialName = credentialName
        deletePermissionEntry__calledWith_actor = actor
    }
}

package org.cloudfoundry.credhub.controllers.v1.permissions

import org.cloudfoundry.credhub.permissions.PermissionsV1Handler
import org.cloudfoundry.credhub.requests.PermissionsRequest
import org.cloudfoundry.credhub.views.PermissionsView

class SpyPermissionsV1Handler : PermissionsV1Handler {
    lateinit var permissionsCalledwithName: String
    lateinit var permissionsReturnsPermissionsview: PermissionsView

    override fun getPermissions(name: String): PermissionsView {
        permissionsCalledwithName = name
        return permissionsReturnsPermissionsview
    }

    lateinit var writepermissionsCalledwithRequest: PermissionsRequest

    override fun writePermissions(request: PermissionsRequest) {
        writepermissionsCalledwithRequest = request
    }

    lateinit var deletepermissionentryCalledwithCredentialname: String
    lateinit var deletepermissionentryCalledwithActor: String

    override fun deletePermissionEntry(
        credentialName: String,
        actor: String,
    ) {
        deletepermissionentryCalledwithCredentialname = credentialName
        deletepermissionentryCalledwithActor = actor
    }
}

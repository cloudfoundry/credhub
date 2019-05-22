package org.cloudfoundry.credhub.permissions

import org.cloudfoundry.credhub.requests.PermissionsRequest
import org.cloudfoundry.credhub.views.PermissionsView
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service

@Service
@Profile("remote")
class RemotePermissionsV1Handler : PermissionsV1Handler{
    override fun getPermissions(name: String): PermissionsView {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun writePermissions(request: PermissionsRequest) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun deletePermissionEntry(credentialName: String, actor: String) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}

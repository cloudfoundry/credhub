package org.cloudfoundry.credhub.permissions

import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.views.PermissionsV2View
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service
import java.util.UUID

@Service
@Profile("remote")
class RemotePermissionsV2Handler : PermissionsV2Handler {
    override fun writePermissions(request: PermissionsV2Request): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun getPermissions(guid: UUID): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun putPermissions(guid: String, permissionsRequest: PermissionsV2Request): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun patchPermissions(guid: String, operations: List<PermissionOperation>): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun writeV2Permissions(permissionsRequest: PermissionsV2Request): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun deletePermissions(guid: String): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findByPathAndActor(path: String, actor: String): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}

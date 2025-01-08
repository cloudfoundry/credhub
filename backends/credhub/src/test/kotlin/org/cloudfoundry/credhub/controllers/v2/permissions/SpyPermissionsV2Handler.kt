package org.cloudfoundry.credhub.controllers.v2.permissions

import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.permissions.PermissionsV2Handler
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.views.PermissionsV2View

class SpyPermissionsV2Handler : PermissionsV2Handler {
    override fun writePermissions(request: PermissionsV2Request): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var permissionsCalledwithGuid: String
    lateinit var permissionbyguidReturns: PermissionsV2View

    override fun getPermissions(guid: String): PermissionsV2View {
        permissionsCalledwithGuid = guid
        return permissionbyguidReturns
    }

    lateinit var putpermissionsCalledwithGuid: String
    lateinit var putpermissionsCalledwithPermissionsrequest: PermissionsV2Request
    lateinit var putpermissionsReturns: PermissionsV2View

    override fun putPermissions(
        guid: String,
        permissionsRequest: PermissionsV2Request,
    ): PermissionsV2View {
        putpermissionsCalledwithGuid = guid
        putpermissionsCalledwithPermissionsrequest = permissionsRequest
        return putpermissionsReturns
    }

    lateinit var patchpermissionsCalledwithGuid: String
    lateinit var patchpermissionsCalledwithOperations: List<PermissionOperation>
    lateinit var patchpermissionsReturns: PermissionsV2View

    override fun patchPermissions(
        guid: String,
        operations: MutableList<PermissionOperation>?,
    ): PermissionsV2View {
        patchpermissionsCalledwithGuid = guid
        if (operations != null) {
            patchpermissionsCalledwithOperations = operations
        }
        return patchpermissionsReturns
    }

    lateinit var writev2permissionsCalledwithPermissionrequest: PermissionsV2Request
    lateinit var writev2permissionsReturns: PermissionsV2View

    override fun writeV2Permissions(permissionsRequest: PermissionsV2Request): PermissionsV2View {
        writev2permissionsCalledwithPermissionrequest = permissionsRequest
        return writev2permissionsReturns
    }

    lateinit var deletepermissionsCalledwithGuid: String
    lateinit var deletepermissionsReturns: PermissionsV2View

    override fun deletePermissions(guid: String): PermissionsV2View {
        deletepermissionsCalledwithGuid = guid
        return deletepermissionsReturns
    }

    lateinit var findbypathandactorCalledwithPath: String
    lateinit var findbypathandactorCalledwithActor: String
    lateinit var findbypathandactorReturns: PermissionsV2View

    override fun findByPathAndActor(
        path: String,
        actor: String,
    ): PermissionsV2View {
        findbypathandactorCalledwithPath = path
        findbypathandactorCalledwithActor = actor
        return findbypathandactorReturns
    }
}

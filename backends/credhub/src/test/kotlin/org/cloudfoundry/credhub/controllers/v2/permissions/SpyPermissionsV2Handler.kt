package org.cloudfoundry.credhub.controllers.v2.permissions

import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.handlers.PermissionsV2Handler
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.views.PermissionsV2View
import java.util.UUID

class SpyPermissionsV2Handler : PermissionsV2Handler {
    override fun writePermissions(request: PermissionsV2Request): PermissionsV2View {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var getPermissions__calledWith_Guid: UUID
    lateinit var getPermissionByGuid__returns: PermissionsV2View
    override fun getPermissions(guid: UUID): PermissionsV2View {
        getPermissions__calledWith_Guid = guid
        return getPermissionByGuid__returns
    }

    lateinit var putPermissions__calledWith_Guid: String
    lateinit var putPermissions__calledWith_PermissionsRequest: PermissionsV2Request
    lateinit var putPermissions__returns: PermissionsV2View
    override fun putPermissions(guid: String, permissionsRequest: PermissionsV2Request): PermissionsV2View {
        putPermissions__calledWith_Guid = guid
        putPermissions__calledWith_PermissionsRequest = permissionsRequest
        return putPermissions__returns
    }

    lateinit var patchPermissions__calledWith_Guid: String
    lateinit var patchPermissions__calledWith_Operations: List<PermissionOperation>
    lateinit var patchPermissions__returns: PermissionsV2View
    override fun patchPermissions(guid: String, operations: List<PermissionOperation>): PermissionsV2View {
        patchPermissions__calledWith_Guid = guid
        patchPermissions__calledWith_Operations = operations
        return patchPermissions__returns
    }

    lateinit var writeV2Permissions__calledWith_PermissionRequest: PermissionsV2Request
    lateinit var writeV2Permissions__returns: PermissionsV2View
    override fun writeV2Permissions(permissionsRequest: PermissionsV2Request): PermissionsV2View {
        writeV2Permissions__calledWith_PermissionRequest = permissionsRequest
        return writeV2Permissions__returns
    }

    lateinit var deletePermissions__calledWith_Guid: String
    lateinit var deletePermissions__returns: PermissionsV2View
    override fun deletePermissions(guid: String): PermissionsV2View {
        deletePermissions__calledWith_Guid = guid
        return deletePermissions__returns
    }

    lateinit var findByPathAndActor__calledWith_Path: String
    lateinit var findByPathAndActor__calledWith_Actor: String
    lateinit var findByPathAndActor__returns: PermissionsV2View
    override fun findByPathAndActor(path: String, actor: String): PermissionsV2View {
        findByPathAndActor__calledWith_Path = path
        findByPathAndActor__calledWith_Actor = actor
        return findByPathAndActor__returns
    }
}

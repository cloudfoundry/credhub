package org.cloudfoundry.credhub.handlers

import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.data.PermissionData
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.services.PermissionService
import java.util.UUID

class SpyPermissionService : PermissionService {
    override fun getAllowedOperationsForLogging(credentialName: String, actor: String): List<PermissionOperation> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var savePermissionsForUser__calledWith_permissionEntryList: MutableList<PermissionEntry>
    lateinit var savePermissionsForUser__returns_permissionDataList: List<PermissionData>
    override fun savePermissionsForUser(permissionEntryList: MutableList<PermissionEntry>): List<PermissionData> {
        savePermissionsForUser__calledWith_permissionEntryList = permissionEntryList
        return savePermissionsForUser__returns_permissionDataList
    }

    override fun savePermissions(permissionEntryList: MutableList<PermissionEntry>) {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var getPermissions__calledWith_credentialVersion: CredentialVersion
    lateinit var getPermissions__returns_permissionEntries: List<PermissionEntry>
    override fun getPermissions(credentialVersion: CredentialVersion?): List<PermissionEntry> {
        getPermissions__calledWith_credentialVersion = credentialVersion!!
        return getPermissions__returns_permissionEntries
    }

    var getPermissions__calledWith_uuid: UUID? = null
    lateinit var getPermissions__returns_permissionData: PermissionData
    override fun getPermissions(guid: UUID?): PermissionData {
        getPermissions__calledWith_uuid = guid

        return getPermissions__returns_permissionData
    }

    lateinit var deletePermissions__calledWith_credentialName: String
    lateinit var deletePermissions__calledWith_actor: String
    var deletePermissions__returns = false
    override fun deletePermissions(credentialName: String, actor: String): Boolean {
        deletePermissions__calledWith_credentialName = credentialName
        deletePermissions__calledWith_actor = actor

        return deletePermissions__returns
    }

    lateinit var putPermissions__calledWith_guid: String
    lateinit var putPermissions__calledWith_permissionsRequest: PermissionsV2Request
    lateinit var putPermissions__returns_permissionData: PermissionData
    override fun putPermissions(guid: String, permissionsRequest: PermissionsV2Request): PermissionData {
        putPermissions__calledWith_guid = guid
        putPermissions__calledWith_permissionsRequest = permissionsRequest

        return putPermissions__returns_permissionData
    }

    lateinit var patchPermissions__calledWith_guid: String
    lateinit var patchPermissions__calledWith_operations: MutableList<PermissionOperation>
    lateinit var patchPermissions__returns_permissionData: PermissionData
    override fun patchPermissions(guid: String, operations: MutableList<PermissionOperation>): PermissionData {
        patchPermissions__calledWith_guid = guid
        patchPermissions__calledWith_operations = operations

        return patchPermissions__returns_permissionData
    }

    lateinit var saveV2Permissions__calledWith_permissionsRequest: PermissionsV2Request
    lateinit var saveV2Permissions__returns_permissionData: PermissionData
    override fun saveV2Permissions(permissionsRequest: PermissionsV2Request): PermissionData {
        saveV2Permissions__calledWith_permissionsRequest = permissionsRequest
        return saveV2Permissions__returns_permissionData
    }

    lateinit var deletePermissions__calledWith_guid: String
    lateinit var deletePermissions__returns_permissionData: PermissionData
    override fun deletePermissions(guid: String): PermissionData {
        deletePermissions__calledWith_guid = guid
        return deletePermissions__returns_permissionData
    }

    lateinit var findByPathAndActor__calledWith_path: String
    lateinit var findByPathAndActor__calledWith_actor: String
    var findByPathAndActor__returns_permissionData: PermissionData? = null
    override fun findByPathAndActor(path: String, actor: String): PermissionData? {
        findByPathAndActor__calledWith_path = path
        findByPathAndActor__calledWith_actor = actor

        return findByPathAndActor__returns_permissionData
    }
}

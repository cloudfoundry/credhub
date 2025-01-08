package org.cloudfoundry.credhub.handlers

import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.data.PermissionData
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.services.PermissionService
import java.util.UUID

class SpyPermissionService : PermissionService {
    override fun getAllowedOperationsForLogging(
        credentialName: String,
        actor: String,
    ): List<PermissionOperation> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var savepermissionsforuserCalledwithPermissionentrylist: MutableList<PermissionEntry>
    lateinit var savepermissionsforuserReturnsPermissiondatalist: MutableList<PermissionData>

    override fun savePermissionsForUser(permissionEntryList: MutableList<PermissionEntry>?): MutableList<PermissionData> {
        if (permissionEntryList != null) {
            savepermissionsforuserCalledwithPermissionentrylist = permissionEntryList
        }
        return savepermissionsforuserReturnsPermissiondatalist
    }

    override fun savePermissions(permissionEntryList: MutableList<PermissionEntry>) {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var permissionsCalledwithCredentialversion: CredentialVersion
    lateinit var permissionsReturnsPermissionentries: List<PermissionEntry>

    override fun getPermissions(credentialVersion: CredentialVersion?): List<PermissionEntry> {
        permissionsCalledwithCredentialversion = credentialVersion!!
        return permissionsReturnsPermissionentries
    }

    var permissionsCalledwithUuid: UUID? = null
    lateinit var permissionsReturnsPermissiondata: PermissionData

    override fun getPermissions(guid: UUID?): PermissionData {
        permissionsCalledwithUuid = guid

        return permissionsReturnsPermissiondata
    }

    lateinit var deletepermissionsCalledwithCredentialname: String
    lateinit var deletepermissionsCalledwithActor: String
    var deletepermissionsReturns = false

    override fun deletePermissions(
        credentialName: String,
        actor: String,
    ): Boolean {
        deletepermissionsCalledwithCredentialname = credentialName
        deletepermissionsCalledwithActor = actor

        return deletepermissionsReturns
    }

    lateinit var putpermissionsCalledwithGuid: String
    lateinit var putpermissionsCalledwithPermissionsrequest: PermissionsV2Request
    lateinit var putpermissionsReturnsPermissiondata: PermissionData

    override fun putPermissions(
        guid: String,
        permissionsRequest: PermissionsV2Request,
    ): PermissionData {
        putpermissionsCalledwithGuid = guid
        putpermissionsCalledwithPermissionsrequest = permissionsRequest

        return putpermissionsReturnsPermissiondata
    }

    lateinit var patchpermissionsCalledwithGuid: String
    lateinit var patchpermissionsCalledwithOperations: MutableList<PermissionOperation>
    lateinit var patchpermissionsReturnsPermissiondata: PermissionData

    override fun patchPermissions(
        guid: String,
        operations: MutableList<PermissionOperation>?,
    ): PermissionData {
        patchpermissionsCalledwithGuid = guid
        if (operations != null) {
            patchpermissionsCalledwithOperations = operations
        }

        return patchpermissionsReturnsPermissiondata
    }

    lateinit var savev2permissionsCalledwithPermissionsrequest: PermissionsV2Request
    lateinit var savev2permissionsReturnsPermissiondata: PermissionData

    override fun saveV2Permissions(permissionsRequest: PermissionsV2Request): PermissionData {
        savev2permissionsCalledwithPermissionsrequest = permissionsRequest
        return savev2permissionsReturnsPermissiondata
    }

    lateinit var deletepermissionsCalledwithGuid: String
    lateinit var deletepermissionsReturnsPermissiondata: PermissionData

    override fun deletePermissions(guid: String): PermissionData {
        deletepermissionsCalledwithGuid = guid
        return deletepermissionsReturnsPermissiondata
    }

    lateinit var findbypathandactorCalledwithPath: String
    lateinit var findbypathandactorCalledwithActor: String
    var findbypathandactorReturnsPermissiondata: PermissionData? = null

    override fun findByPathAndActor(
        path: String,
        actor: String,
    ): PermissionData? {
        findbypathandactorCalledwithPath = path
        findbypathandactorCalledwithActor = actor

        return findbypathandactorReturnsPermissiondata
    }
}

package org.cloudfoundry.credhub.services

import java.util.UUID
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.data.PermissionData
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsV2Request

interface PermissionService {

    fun getAllowedOperationsForLogging(credentialName: String, actor: String): List<PermissionOperation>

    fun savePermissionsForUser(permissionEntryList: MutableList<PermissionEntry>): List<PermissionData>

    fun savePermissions(permissionEntryList: MutableList<PermissionEntry>)

    fun getPermissions(credentialVersion: CredentialVersion?): List<PermissionEntry>

    fun getPermissions(guid: UUID?): PermissionData

    fun deletePermissions(credentialName: String, actor: String): Boolean

    fun putPermissions(guid: String, permissionsRequest: PermissionsV2Request): PermissionData

    fun patchPermissions(guid: String, operations: MutableList<PermissionOperation>): PermissionData

    fun saveV2Permissions(permissionsRequest: PermissionsV2Request): PermissionData

    fun deletePermissions(guid: String): PermissionData

    fun findByPathAndActor(path: String, actor: String): PermissionData?
}

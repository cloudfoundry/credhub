package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.data.PermissionData
import org.cloudfoundry.credhub.data.PermissionDataService
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.InvalidPermissionException
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException
import org.cloudfoundry.credhub.exceptions.PermissionAlreadyExistsException
import org.cloudfoundry.credhub.exceptions.PermissionDoesNotExistException
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.util.ArrayList
import java.util.UUID

@Service
class DefaultPermissionService @Autowired
constructor(
    private val permissionDataService: PermissionDataService,
    private val permissionCheckingService: PermissionCheckingService,
    private val userContextHolder: UserContextHolder
) : PermissionService {

    override fun getAllowedOperationsForLogging(credentialName: String, actor: String): List<PermissionOperation> {
        return permissionDataService.getAllowedOperations(credentialName, actor)
    }

    override fun savePermissionsForUser(permissionEntryList: MutableList<PermissionEntry>?): List<PermissionData> {

        if (permissionEntryList?.isEmpty() as Boolean) {
            return ArrayList()
        }

        val userContext = userContextHolder.userContext
        permissionEntryList.forEach { permissionEntry ->
            if (!permissionCheckingService
                .hasPermission(userContext?.actor!!, permissionEntry.path!!, PermissionOperation.WRITE_ACL)
            ) {
                throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
            }
            if (!permissionCheckingService.userAllowedToOperateOnActor(permissionEntry.actor)) {
                throw InvalidPermissionOperationException(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION)
            }
            if (permissionCheckingService.hasPermissions(
                    permissionEntry.actor!!, permissionEntry.path!!,
                    permissionEntry.allowedOperations!!
                )
            ) {
                throw PermissionAlreadyExistsException(ErrorMessages.Permissions.ALREADY_EXISTS)
            }
        }
        return permissionDataService.savePermissionsWithLogging(permissionEntryList)
    }

    override fun savePermissions(permissionEntryList: MutableList<PermissionEntry>) {
        if (permissionEntryList.isEmpty()) {
            return
        }
        permissionDataService.savePermissions(permissionEntryList)
    }

    override fun getPermissions(credentialVersion: CredentialVersion?): MutableList<PermissionEntry> {
        if (credentialVersion == null) {
            throw EntryNotFoundException(ErrorMessages.RESOURCE_NOT_FOUND)
        }

        if (!permissionCheckingService
            .hasPermission(
                    userContextHolder.userContext?.actor!!, credentialVersion.name!!,
                    PermissionOperation.READ_ACL
                )
        ) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        return getPermissions(credentialVersion.credential!!)
    }

    override fun getPermissions(guid: UUID?): PermissionData? {
        if (guid == null) {
            throw EntryNotFoundException(ErrorMessages.RESOURCE_NOT_FOUND)
        }

        if (!permissionCheckingService
            .hasPermission(userContextHolder.userContext?.actor!!, guid, PermissionOperation.READ_ACL)
        ) {
            throw InvalidPermissionException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        return permissionDataService.getPermission(guid)
    }

    override fun deletePermissions(credentialName: String, actor: String): Boolean {
        if (!permissionCheckingService
            .hasPermission(userContextHolder.userContext?.actor!!, credentialName, PermissionOperation.WRITE_ACL)
        ) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        if (!permissionCheckingService.userAllowedToOperateOnActor(actor)) {
            throw InvalidPermissionOperationException(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION)
        }

        return permissionDataService.deletePermissions(credentialName, actor)
    }

    override fun putPermissions(guid: String, permissionsRequest: PermissionsV2Request): PermissionData {
        val userContext = userContextHolder.userContext
        val permissionUUID = parseUUID(guid)
        checkActorPermissions(permissionUUID, userContext?.actor)

        return permissionDataService.putPermissions(guid, permissionsRequest)
    }

    override fun patchPermissions(guid: String, operations: MutableList<PermissionOperation>?): PermissionData {
        val userContext = userContextHolder.userContext
        val permissionUUID = parseUUID(guid)
        checkActorPermissions(permissionUUID, userContext?.actor)

        return permissionDataService.patchPermissions(guid, operations)
    }

    override fun saveV2Permissions(permissionsRequest: PermissionsV2Request): PermissionData {
        val userContext = userContextHolder.userContext
        if (!permissionCheckingService
            .hasPermission(userContext?.actor!!, permissionsRequest.getPath(), PermissionOperation.WRITE_ACL)
        ) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
        if (!permissionCheckingService.userAllowedToOperateOnActor(permissionsRequest.actor)) {
            throw InvalidPermissionOperationException(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION)
        }
        return permissionDataService.saveV2Permissions(permissionsRequest)
    }

    override fun deletePermissions(guid: String): PermissionData {
        val userContext = userContextHolder.userContext
        val permissionUUID = parseUUID(guid)
        checkActorPermissions(permissionUUID, userContext?.actor)
        return permissionDataService.deletePermissions(permissionUUID)
    }

    override fun findByPathAndActor(path: String, actor: String): PermissionData? {
        val userContext = userContextHolder.userContext
        if (!permissionCheckingService.hasPermission(userContext?.actor!!, path, PermissionOperation.READ_ACL)) {
            throw EntryNotFoundException(ErrorMessages.Permissions.INVALID_ACCESS)
        }
        return permissionDataService.findByPathAndActor(path, actor)
    }

    private fun checkActorPermissions(permissionUUID: UUID, actor: String?) {
        if (!permissionCheckingService.hasPermission(actor!!, permissionUUID, PermissionOperation.WRITE_ACL)) {
            throw EntryNotFoundException(ErrorMessages.Permissions.DOES_NOT_EXIST)
        }
        if (!permissionCheckingService.userAllowedToOperateOnActor(permissionUUID)) {
            throw InvalidPermissionOperationException(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION)
        }
    }

    private fun parseUUID(guid: String): UUID {
        val permissionUUID: UUID
        try {
            permissionUUID = UUID.fromString(guid)
        } catch (e: IllegalArgumentException) {
            throw PermissionDoesNotExistException(ErrorMessages.Permissions.DOES_NOT_EXIST)
        }

        return permissionUUID
    }

    private fun getPermissions(credential: Credential): MutableList<PermissionEntry> {
        return permissionDataService.getPermissions(credential)
    }
}

package org.cloudfoundry.credhub.permissions

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.services.PermissionService
import org.cloudfoundry.credhub.views.PermissionsV2View
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import java.util.UUID

@Profile("!remote")
@Component
class DefaultPermissionsV2Handler(
    private val permissionService: PermissionService,
) : PermissionsV2Handler {

    companion object {
        const val INVALID_NUMBER_OF_PERMISSIONS = "Can set one permission per call"
    }

    override fun writePermissions(request: PermissionsV2Request): PermissionsV2View {
        val permission = PermissionEntry(request.actor, request.getPath(), request.operations)
        val permissionDatas = permissionService.savePermissionsForUser(mutableListOf(permission))

        if (permissionDatas.size == 1) {
            val perm = permissionDatas[0]
            return PermissionsV2View(
                perm.path,
                perm.generateAccessControlOperations(),
                perm.actor,
                perm.uuid,
            )
        } else {
            throw IllegalArgumentException(INVALID_NUMBER_OF_PERMISSIONS)
        }
    }

    override fun getPermissions(guid: String): PermissionsV2View {
        val uuid = try {
            UUID.fromString(guid)
        } catch (e: IllegalArgumentException) {
            throw EntryNotFoundException(ErrorMessages.Permissions.INVALID_ACCESS)
        }
        val permission = permissionService.getPermissions(uuid)
        return PermissionsV2View(
            permission?.path,
            permission?.generateAccessControlOperations(),
            permission?.actor,
            uuid,
        )
    }

    override fun putPermissions(guid: String, permissionsRequest: PermissionsV2Request): PermissionsV2View {
        val permission = permissionService.putPermissions(guid, permissionsRequest)
        return PermissionsV2View(
            permission.path,
            permission.generateAccessControlOperations(),
            permission.actor,
            permission.uuid,
        )
    }

    override fun patchPermissions(guid: String, operations: MutableList<PermissionOperation>?): PermissionsV2View {
        val permission = permissionService.patchPermissions(guid, operations)
        return PermissionsV2View(
            permission.path,
            permission.generateAccessControlOperations(),
            permission.actor,
            permission.uuid,
        )
    }

    override fun writeV2Permissions(permissionsRequest: PermissionsV2Request): PermissionsV2View {
        val permission = permissionService.saveV2Permissions(permissionsRequest)
        return PermissionsV2View(
            permission.path,
            permission.generateAccessControlOperations(),
            permission.actor,
            permission.uuid,
        )
    }

    override fun deletePermissions(guid: String): PermissionsV2View {
        val permission = permissionService.deletePermissions(guid)
        return PermissionsV2View(
            permission.path,
            permission.generateAccessControlOperations(),
            permission.actor,
            permission.uuid,
        )
    }

    override fun findByPathAndActor(path: String, actor: String): PermissionsV2View {
        val permissionData = permissionService.findByPathAndActor(path, actor)
            ?: throw EntryNotFoundException(ErrorMessages.Permissions.INVALID_ACCESS)

        return PermissionsV2View(
            permissionData.path,
            permissionData.generateAccessControlOperations(),
            permissionData.actor,
            permissionData.uuid,
        )
    }
}

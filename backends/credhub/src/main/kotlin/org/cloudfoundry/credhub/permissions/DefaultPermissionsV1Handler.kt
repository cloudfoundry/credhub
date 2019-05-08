package org.cloudfoundry.credhub.permissions

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.requests.PermissionsRequest
import org.cloudfoundry.credhub.services.CredentialService
import org.cloudfoundry.credhub.services.PermissionService
import org.cloudfoundry.credhub.views.PermissionsView
import org.springframework.stereotype.Component

@Component
class DefaultPermissionsV1Handler(
    private val permissionService: PermissionService,
    private val credentialService: CredentialService
) : PermissionsV1Handler {

    override fun getPermissions(name: String): PermissionsView {
        val credentialVersion = credentialService.findMostRecent(name)
        val permissions = permissionService.getPermissions(credentialVersion)
        return PermissionsView(credentialVersion!!.name, permissions)
    }

    override fun writePermissions(request: PermissionsRequest) {
        for (entry in request.permissions) {
            entry.path = request.credentialName
        }
        permissionService.savePermissionsForUser(request.permissions)
    }

    override fun deletePermissionEntry(credentialName: String, actor: String) {
        val successfullyDeleted = permissionService.deletePermissions(credentialName, actor)
        if (!successfullyDeleted) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
    }
}

package org.cloudfoundry.credhub.permissions

import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.entities.AddPermission
import org.cloudfoundry.credhub.audit.entities.DeletePermissions
import org.cloudfoundry.credhub.audit.entities.GetPermissions
import org.cloudfoundry.credhub.requests.PermissionsRequest
import org.cloudfoundry.credhub.views.PermissionsView
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(path = [PermissionsV1Controller.ENDPOINT], produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
class PermissionsV1Controller(
    private val permissionsHandler: PermissionsV1Handler,
    private val auditRecord: CEFAuditRecord
) {
    companion object {
        const val ENDPOINT = "/api/v1/permissions"
    }

    @RequestMapping(method = [RequestMethod.GET], path = [""])
    @ResponseStatus(HttpStatus.OK)
    fun getAccessControlList(@RequestParam("credential_name") credentialName: String): PermissionsView {
        val credentialNameWithLeadingSlash = StringUtils.prependIfMissing(credentialName, "/")
        auditRecord.requestDetails = GetPermissions(credentialName)

        return permissionsHandler.getPermissions(credentialNameWithLeadingSlash)
    }

    @RequestMapping(method = [RequestMethod.POST], path = [""], consumes = [MediaType.APPLICATION_JSON_UTF8_VALUE])
    @ResponseStatus(HttpStatus.CREATED)
    fun setAccessControlEntries(@Validated @RequestBody accessEntriesRequest: PermissionsRequest) {
        val addPermission = AddPermission(accessEntriesRequest.credentialName,
            accessEntriesRequest.permissions)
        auditRecord.requestDetails = addPermission
        permissionsHandler.writePermissions(accessEntriesRequest)
    }

    @RequestMapping(method = [RequestMethod.DELETE], path = [""])
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun deleteAccessControlEntry(
        @RequestParam("credential_name") credentialName: String,
        @RequestParam("actor") actor: String
    ) {
        val credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/")

        val deletePermissions = DeletePermissions(credentialName, actor)
        auditRecord.requestDetails = deletePermissions

        permissionsHandler.deletePermissionEntry(credentialNameWithPrependedSlash, actor)
    }
}

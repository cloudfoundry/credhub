package org.cloudfoundry.credhub.permissions

import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.handlers.PermissionsV2Handler
import org.cloudfoundry.credhub.requests.PermissionsV2PatchRequest
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.views.PermissionsV2View
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping(
    path = [PermissionsV2Controller.ENDPOINT],
    produces = [MediaType.APPLICATION_JSON_UTF8_VALUE]
)
class PermissionsV2Controller(private val permissionsHandler: PermissionsV2Handler) {

    companion object {

        const val ENDPOINT = "/api/v2/permissions"
    }

    @RequestMapping(
        method = [RequestMethod.POST],
        path = [""],
        consumes = [MediaType.APPLICATION_JSON_UTF8_VALUE]
    )
    @ResponseStatus(HttpStatus.CREATED)
    fun postPermissions(@Validated @RequestBody permissionsRequest: PermissionsV2Request): PermissionsV2View {
        return permissionsHandler.writeV2Permissions(permissionsRequest)
    }

    @RequestMapping(method = [RequestMethod.GET], path = ["/{guid}"])
    @ResponseStatus(HttpStatus.OK)
    fun getPermissions(@PathVariable guid: String): PermissionsV2View {
        return permissionsHandler.getPermissions(UUID.fromString(guid))
    }

    @RequestMapping(method = [RequestMethod.GET])
    @ResponseStatus(HttpStatus.OK)
    fun findByPathAndActor(
        @RequestParam path: String,
        @RequestParam actor: String
    ): PermissionsV2View {
        val pathWithPrependedSlash = StringUtils.prependIfMissing(path, "/")

        return permissionsHandler.findByPathAndActor(pathWithPrependedSlash, actor)
    }

    @RequestMapping(method = [RequestMethod.PUT], path = ["/{guid}"] )
    @ResponseStatus(HttpStatus.OK)
    fun putPermissions(
        @Validated @RequestBody permissionsRequest: PermissionsV2Request,
        @PathVariable guid: String
    ): PermissionsV2View {
        return permissionsHandler.putPermissions(guid, permissionsRequest)
    }

    @RequestMapping(method = [RequestMethod.PATCH], path = ["/{guid}"] )
    @ResponseStatus(HttpStatus.OK)
    fun patchPermissions(
        @Validated @RequestBody request: PermissionsV2PatchRequest,
        @PathVariable guid: String
    ): PermissionsV2View {
        return permissionsHandler.patchPermissions(guid, request.operations)
    }

    @RequestMapping(method = [RequestMethod.DELETE], path = ["/{guid}"] )
    @ResponseStatus(HttpStatus.OK)
    fun deletePermissions(@PathVariable guid: String): PermissionsV2View {
        return permissionsHandler.deletePermissions(guid)
    }
}

package org.cloudfoundry.credhub.interpolation

import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.entities.InterpolateCredentials
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(path = [InterpolationController.ENDPOINT], produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
class InterpolationController(
    private val jsonInterpolationHandler: InterpolationHandler,
    private val auditRecord: CEFAuditRecord
) {

    companion object {
        const val ENDPOINT = "/api/v1/interpolate"
    }

    @RequestMapping(method = [RequestMethod.POST], path = [""])
    @ResponseStatus(HttpStatus.OK)
    fun interpolate(@RequestBody requestBody: Map<String, Any>): Map<String, Any> {
        auditRecord.requestDetails = InterpolateCredentials()
        return jsonInterpolationHandler.interpolateCredHubReferences(requestBody)
    }
}

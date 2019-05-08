package org.cloudfoundry.credhub.regenerate

import org.cloudfoundry.credhub.exceptions.PermissionException
import org.cloudfoundry.credhub.requests.BulkRegenerateRequest
import org.cloudfoundry.credhub.requests.RegenerateRequest
import org.cloudfoundry.credhub.views.BulkRegenerateResults
import org.cloudfoundry.credhub.views.CredentialView
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.transaction.annotation.Transactional
import org.springframework.validation.annotation.Validated
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import javax.validation.Valid

@RestController
class RegenerateController(val regenerateHandler: RegenerateHandler) {
    companion object {
        const val REGENERATE_ENDPOINT = "api/v1/regenerate"
        const val BULK_REGENERATE_ENDPOINT = "api/v1/bulk-regenerate"
    }

    @PostMapping(path = [REGENERATE_ENDPOINT], produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
    @ResponseStatus(HttpStatus.OK)
    fun regenerate(@RequestBody @Validated requestBody: RegenerateRequest): CredentialView {
        return regenerateHandler.handleRegenerate(requestBody.name)
    }

    @PostMapping(path = [BULK_REGENERATE_ENDPOINT], produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
    @ResponseStatus(HttpStatus.OK)
    @Transactional(rollbackFor = [PermissionException::class])
    fun bulkRegenerate(@RequestBody @Valid requestBody: BulkRegenerateRequest): BulkRegenerateResults {
        return regenerateHandler.handleBulkRegenerate(requestBody.signedBy)
    }
}

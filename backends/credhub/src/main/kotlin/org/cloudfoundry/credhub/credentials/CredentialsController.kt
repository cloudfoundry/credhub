package org.cloudfoundry.credhub.credentials

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.IOException
import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.entities.DeleteCredential
import org.cloudfoundry.credhub.audit.entities.FindCredential
import org.cloudfoundry.credhub.audit.entities.GenerateCredential
import org.cloudfoundry.credhub.audit.entities.GetCredential
import org.cloudfoundry.credhub.audit.entities.RegenerateCredential
import org.cloudfoundry.credhub.audit.entities.SetCredential
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException
import org.cloudfoundry.credhub.regenerate.RegenerateHandler
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.requests.CredentialRegenerateRequest
import org.cloudfoundry.credhub.views.CredentialView
import org.cloudfoundry.credhub.views.DataResponse
import org.cloudfoundry.credhub.views.FindCredentialResults
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod.DELETE
import org.springframework.web.bind.annotation.RequestMethod.GET
import org.springframework.web.bind.annotation.RequestMethod.POST
import org.springframework.web.bind.annotation.RequestMethod.PUT
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(
    path = [CredentialsController.ENDPOINT],
    produces = [MediaType.APPLICATION_JSON_UTF8_VALUE]
)
class CredentialsController(
    private val credentialsHandler: CredentialsHandler,
    private val auditRecord: CEFAuditRecord,
    val regenerateHandler: RegenerateHandler,
    private val objectMapper: ObjectMapper
) {
    companion object {
        const val ENDPOINT = "/api/v1/data"
    }

    @RequestMapping(method = [GET], path = ["/{id}"])
    @ResponseStatus(HttpStatus.OK)
    fun getById(@PathVariable id: String): CredentialView {
        return credentialsHandler.getCredentialVersionByUUID(id)
    }

    @RequestMapping(method = [GET], path = [""])
    @ResponseStatus(HttpStatus.OK)
    fun getByName(
        @RequestParam("name") credentialName: String,
        @RequestParam(value = "versions", required = false) numberOfVersions: Int?,
        @RequestParam(value = "current", required = false, defaultValue = "false") current: Boolean
    ): DataResponse {
        if (StringUtils.isEmpty(credentialName)) {
            throw InvalidQueryParameterException(ErrorMessages.MISSING_QUERY_PARAMETER, "name")
        }

        if (current && numberOfVersions != null) {
            throw InvalidQueryParameterException(ErrorMessages.CANT_USE_VERSIONS_AND_CURRENT, "name")
        }

        val credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/")

        auditRecord.requestDetails = GetCredential(credentialName, numberOfVersions, current)

        return if (current) {
            credentialsHandler.getCurrentCredentialVersions(credentialNameWithPrependedSlash)
        } else {
            credentialsHandler.getNCredentialVersions(credentialNameWithPrependedSlash, numberOfVersions)
        }
    }

    @RequestMapping(method = [GET], path = [""], params = ["path"])
    @ResponseStatus(HttpStatus.OK)
    fun findByPath(
        @RequestParam("path") path: String,
        @RequestParam(value = "expires-within-days", required = false, defaultValue = "") expiresWithinDays: String
    ): FindCredentialResults {
        val findCredential = FindCredential()
        findCredential.path = path
        findCredential.expiresWithinDays = expiresWithinDays
        auditRecord.requestDetails = findCredential

        return FindCredentialResults(credentialsHandler.findStartingWithPath(path, expiresWithinDays))
    }

    @RequestMapping(method = [GET], path = [""], params = ["name-like"])
    @ResponseStatus(HttpStatus.OK)
    fun findByNameLike(
        @RequestParam("name-like") nameLike: String,
        @RequestParam(value = "expires-within-days", required = false, defaultValue = "") expiresWithinDays: String
    ): FindCredentialResults {
        val findCredential = FindCredential()
        findCredential.nameLike = nameLike
        findCredential.expiresWithinDays = expiresWithinDays
        auditRecord.requestDetails = findCredential

        return FindCredentialResults(credentialsHandler.findContainingName(nameLike, expiresWithinDays))
    }

    @Synchronized
    @RequestMapping(method = [POST], path = [""])
    @ResponseStatus(HttpStatus.OK)
    @Throws(IOException::class)
    fun generate(@RequestBody request: JsonNode): CredentialView {
        val isRegenerate = request["regenerate"]?.asBoolean() ?: false
        try {
            if (isRegenerate) {
                val regenerateRequest = objectMapper.readValue(request.toString(), CredentialRegenerateRequest::class.java)
                regenerateRequest.validate()
                val regenerateCredential = RegenerateCredential()
                regenerateCredential.name = regenerateRequest.name
                auditRecord.requestDetails = regenerateCredential

                return regenerateHandler.handleRegenerate(regenerateRequest.name)
            } else {
                val requestString = request.toString()
                val generateRequest = objectMapper.readValue(requestString, BaseCredentialGenerateRequest::class.java)
                generateRequest.validate()
                val generateCredential = GenerateCredential()
                generateCredential.name = generateRequest.name
                generateCredential.type = generateRequest.type
                auditRecord.requestDetails = generateCredential

                return credentialsHandler.generateCredential(generateRequest)
            }
        } catch (e: IOException) {
            throw RuntimeException(e)
        }
    }

    @RequestMapping(method = [PUT], path = [""])
    @ResponseStatus(HttpStatus.OK)
    @Synchronized
    fun set(@RequestBody requestBody: BaseCredentialSetRequest<*>): CredentialView {
        requestBody.validate()
        auditRecord.requestDetails = SetCredential(requestBody.name, requestBody.type)

        return credentialsHandler.setCredential(requestBody)
    }

    @RequestMapping(method = [DELETE], path = [""])
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun delete(@RequestParam("name") credentialName: String) {
        if (StringUtils.isEmpty(credentialName)) {
            throw InvalidQueryParameterException(ErrorMessages.MISSING_QUERY_PARAMETER, "name")
        }

        val credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/")

        val requestDetails = DeleteCredential(credentialNameWithPrependedSlash)
        auditRecord.requestDetails = requestDetails

        credentialsHandler.deleteCredential(credentialNameWithPrependedSlash)
    }
}

package org.cloudfoundry.credhub.certificates

import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.entities.GetCertificateByName
import org.cloudfoundry.credhub.audit.entities.RegenerateCertificate
import org.cloudfoundry.credhub.audit.entities.UpdateTransitionalVersion
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.requests.CreateVersionRequest
import org.cloudfoundry.credhub.requests.UpdateTransitionalVersionRequest
import org.cloudfoundry.credhub.views.CertificateCredentialsView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView
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

@RestController
@RequestMapping(path = [CertificatesController.ENDPOINT], produces = [MediaType.APPLICATION_JSON_UTF8_VALUE])
class CertificatesController(
    val certificatesHandler: CertificatesHandler,
    val auditRecord: CEFAuditRecord
) {

    companion object {
        const val ENDPOINT = "/api/v1/certificates"
    }

    @RequestMapping(method = [RequestMethod.GET], path = [""])
    @ResponseStatus(HttpStatus.OK)
    fun getAllCertificates(): CertificateCredentialsView {
        auditRecord.setRequestDetails { OperationDeviceAction.GET_ALL_CERTIFICATES }

        return certificatesHandler.handleGetAllRequest()
    }

    @RequestMapping(method = [RequestMethod.GET], path = [""], params = ["name"])
    @ResponseStatus(HttpStatus.OK)
    fun getCertificateByName(@RequestParam("name") name: String): CertificateCredentialsView {
        val credentialName = StringUtils.prependIfMissing(name, "/")
        val details = GetCertificateByName()
        details.name = name
        auditRecord.requestDetails = details

        return certificatesHandler.handleGetByNameRequest(credentialName)
    }

    @RequestMapping(method = [RequestMethod.POST], path = ["/{certificateId}/regenerate"])
    @ResponseStatus(HttpStatus.OK)
    fun regenerateCertificate(
        @PathVariable("certificateId") certificateId: String,
        @RequestBody(required = false) requestBody: CertificateRegenerateRequest?
    ): CredentialView {
        val finalRequestBody = requestBody ?: CertificateRegenerateRequest()
        val certificate = RegenerateCertificate()
        certificate.transitional = finalRequestBody.isTransitional
        auditRecord.requestDetails = certificate

        return certificatesHandler.handleRegenerate(certificateId, finalRequestBody)
    }

    @RequestMapping(method = [RequestMethod.PUT], path = ["/{certificateId}/update_transitional_version"])
    @ResponseStatus(HttpStatus.OK)
    fun updateTransitionalVersion(
        @PathVariable("certificateId") certificateId: String,
        @RequestBody requestBody: UpdateTransitionalVersionRequest
    ): List<CertificateView> {
        val details = UpdateTransitionalVersion()
        details.version = requestBody.versionUuid
        auditRecord.requestDetails = details

        return certificatesHandler.handleUpdateTransitionalVersion(certificateId, requestBody)
    }

    @RequestMapping(method = [RequestMethod.GET], path = ["{certificateId}/versions"])
    @ResponseStatus(HttpStatus.OK)
    fun getAllCertificateVersions(
        @PathVariable("certificateId") certificateId: String,
        @RequestParam(value = "current", required = false, defaultValue = "false") current: Boolean
    ): List<CertificateView> {
        return certificatesHandler.handleGetAllVersionsRequest(certificateId, current)
    }

    @RequestMapping(method = [RequestMethod.POST], path = ["{certificateId}/versions"])
    @ResponseStatus(HttpStatus.OK)
    fun createVersion(
        @RequestBody @Validated requestBody: CreateVersionRequest,
        @PathVariable("certificateId") certificateId: String
    ): CertificateView {
        return certificatesHandler.handleCreateVersionsRequest(certificateId, requestBody)
    }

    @RequestMapping(method = [RequestMethod.DELETE], path = ["{certificateId}/versions/{versionId}"])
    @ResponseStatus(HttpStatus.OK)
    fun deleteVersion(
        @PathVariable("certificateId") certificateId: String,
        @PathVariable("versionId") versionId: String
    ): CertificateView {
        return certificatesHandler.handleDeleteVersionRequest(certificateId, versionId)
    }
}

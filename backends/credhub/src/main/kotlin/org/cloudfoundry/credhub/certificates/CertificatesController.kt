package org.cloudfoundry.credhub.certificates

import org.apache.logging.log4j.LogManager
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.entities.RegenerateCertificate
import org.cloudfoundry.credhub.management.ManagementController
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.views.CredentialView
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
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
        private val LOGGER = LogManager.getLogger(ManagementController::class.java)

    }

    @RequestMapping(method = [RequestMethod.POST], path = ["/{certificateId}/regenerate"])
    @ResponseStatus(HttpStatus.OK)
    fun regenerateCertificate(@PathVariable("certificateId") certificateId: String,
                   @RequestBody(required = false) requestBody: CertificateRegenerateRequest?): CredentialView {

        LOGGER.info(certificateId)

        val finalRequestBody = requestBody ?: CertificateRegenerateRequest()
        val certificate = RegenerateCertificate()
        certificate.transitional = finalRequestBody.isTransitional
        auditRecord.requestDetails = certificate

        return certificatesHandler.handleRegenerate(certificateId, finalRequestBody)
    }
}
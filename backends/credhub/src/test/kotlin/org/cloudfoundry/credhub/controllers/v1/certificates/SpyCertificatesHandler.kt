package org.cloudfoundry.credhub.controllers.v1.certificates

import org.cloudfoundry.credhub.certificates.CertificatesHandler
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.requests.CreateVersionRequest
import org.cloudfoundry.credhub.requests.UpdateTransitionalVersionRequest
import org.cloudfoundry.credhub.views.CertificateCredentialsView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView

class SpyCertificatesHandler : CertificatesHandler {

    lateinit var handleRegenerate__calledWith_credentialUuid: String
    lateinit var handleRegenerate__calledWith_request: CertificateRegenerateRequest
    lateinit var handleRegenerate__returns_credentialView: CredentialView
    override fun handleRegenerate(credentialUuid: String, request: CertificateRegenerateRequest): CredentialView {
        handleRegenerate__calledWith_credentialUuid = credentialUuid
        handleRegenerate__calledWith_request = request

        return handleRegenerate__returns_credentialView
    }

    lateinit var handleGetAllRequest__returns_certificateCredentialsView: CertificateCredentialsView
    override fun handleGetAllRequest(): CertificateCredentialsView {
        return handleGetAllRequest__returns_certificateCredentialsView
    }

    lateinit var handleGetByNameRequest__calledWith_name: String
    lateinit var handleGetByNameRequest__returns_certificateCredentialsView: CertificateCredentialsView
    override fun handleGetByNameRequest(name: String): CertificateCredentialsView {
        handleGetByNameRequest__calledWith_name = name
        return handleGetByNameRequest__returns_certificateCredentialsView
    }

    lateinit var handleGetAllVersionsRequest__calledWith_uuid: String
    var handleGetAllVersionsRequest__calledWith_current = false
    lateinit var handleGetAllVersionsRequest__returns_certificateViews: List<CertificateView>
    override fun handleGetAllVersionsRequest(uuidString: String, current: Boolean): List<CertificateView> {
        handleGetAllVersionsRequest__calledWith_uuid = uuidString
        handleGetAllVersionsRequest__calledWith_current = current

        return handleGetAllVersionsRequest__returns_certificateViews
    }

    lateinit var handleDeleteVersionRequest__calledWith_certificateId: String
    lateinit var handleDeleteVersionRequest__calledWith_versionId: String
    lateinit var handleDeleteVersionRequest__returns_certificateView: CertificateView
    override fun handleDeleteVersionRequest(certificateId: String, versionId: String): CertificateView {
        handleDeleteVersionRequest__calledWith_certificateId = certificateId
        handleDeleteVersionRequest__calledWith_versionId = versionId

        return handleDeleteVersionRequest__returns_certificateView
    }

    lateinit var handleUpdateTransitionalVersion__calledWith_certificateId: String
    lateinit var handleUpdateTransitionalVersion__calledWith_requestBody: UpdateTransitionalVersionRequest
    lateinit var handleUpdateTransitionalVersion__returns_certificateViewList: List<CertificateView>
    override fun handleUpdateTransitionalVersion(certificateId: String, requestBody: UpdateTransitionalVersionRequest): List<CertificateView> {
        handleUpdateTransitionalVersion__calledWith_certificateId = certificateId
        handleUpdateTransitionalVersion__calledWith_requestBody = requestBody
        return handleUpdateTransitionalVersion__returns_certificateViewList
    }

    lateinit var handleCreateVersionRequest__calledWith_certificateId: String
    lateinit var handleCreateVersionRequest__calledWith_requestBody: CreateVersionRequest
    lateinit var handleCreateVersionRequest__returns_certificateView: CertificateView
    override fun handleCreateVersionsRequest(certificateId: String, requestBody: CreateVersionRequest): CertificateView {
        handleCreateVersionRequest__calledWith_certificateId = certificateId
        handleCreateVersionRequest__calledWith_requestBody = requestBody

        return handleCreateVersionRequest__returns_certificateView
    }
}

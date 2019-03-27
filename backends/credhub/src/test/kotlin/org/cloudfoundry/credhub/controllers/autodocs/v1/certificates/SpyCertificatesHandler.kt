package org.cloudfoundry.credhub.controllers.autodocs.v1.certificates

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

    override fun handleGetAllRequest(): CertificateCredentialsView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleGetByNameRequest(name: String): CertificateCredentialsView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleGetAllVersionsRequest(uuidString: String, current: Boolean): List<CertificateView> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleDeleteVersionRequest(certificateId: String, versionId: String): CertificateView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleUpdateTransitionalVersion(certificateId: String, requestBody: UpdateTransitionalVersionRequest): List<CertificateView> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleCreateVersionsRequest(certificateId: String, requestBody: CreateVersionRequest): CertificateView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}
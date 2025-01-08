package org.cloudfoundry.credhub.certificates

import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.requests.CreateVersionRequest
import org.cloudfoundry.credhub.requests.UpdateTransitionalVersionRequest
import org.cloudfoundry.credhub.views.CertificateCredentialsView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service

@Profile("remote")
@Service
class RemoteCertificatesHandler : CertificatesHandler {
    override fun handleRegenerate(
        credentialUuid: String,
        request: CertificateRegenerateRequest,
    ): CredentialView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleGetAllRequest(): CertificateCredentialsView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleGetByNameRequest(name: String): CertificateCredentialsView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleGetAllVersionsRequest(
        certificateId: String,
        current: Boolean,
    ): List<CertificateView> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleDeleteVersionRequest(
        certificateId: String,
        versionId: String,
    ): CertificateView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleUpdateTransitionalVersion(
        certificateId: String,
        requestBody: UpdateTransitionalVersionRequest,
    ): List<CertificateView> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun handleCreateVersionsRequest(
        certificateId: String,
        requestBody: CreateVersionRequest,
    ): CertificateView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}

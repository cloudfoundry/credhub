package org.cloudfoundry.credhub.certificates

import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.requests.CreateVersionRequest
import org.cloudfoundry.credhub.requests.UpdateTransitionalVersionRequest
import org.cloudfoundry.credhub.views.CertificateCredentialsView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView

interface CertificatesHandler {

    fun handleRegenerate(credentialUuid: String, request: CertificateRegenerateRequest): CredentialView

    fun handleGetAllRequest(): CertificateCredentialsView

    fun handleGetByNameRequest(name: String): CertificateCredentialsView

    fun handleGetAllVersionsRequest(uuidString: String, current: Boolean): List<CertificateView>

    fun handleDeleteVersionRequest(certificateId: String, versionId: String): CertificateView

    fun handleUpdateTransitionalVersion(
        certificateId: String,
        requestBody: UpdateTransitionalVersionRequest
    ): List<CertificateView>

    fun handleCreateVersionsRequest(certificateId: String, requestBody: CreateVersionRequest): CertificateView
}
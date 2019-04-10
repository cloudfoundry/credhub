package org.cloudfoundry.credhub.certificates

import com.google.common.collect.Lists
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.audit.AuditableCredential
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.generate.GenerationRequestGenerator
import org.cloudfoundry.credhub.generate.UniversalCredentialGenerator
import org.cloudfoundry.credhub.permissions.PermissionedCertificateService
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.requests.CreateVersionRequest
import org.cloudfoundry.credhub.requests.UpdateTransitionalVersionRequest
import org.cloudfoundry.credhub.views.CertificateCredentialView
import org.cloudfoundry.credhub.views.CertificateCredentialsView
import org.cloudfoundry.credhub.views.CertificateVersionView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class DefaultCertificatesHandler(
    private val permissionedCertificateService: PermissionedCertificateService,
    private val certificateService: CertificateService,
    private val credentialGenerator: UniversalCredentialGenerator,
    private val generationRequestGenerator: GenerationRequestGenerator,
    private val auditRecord: CEFAuditRecord
) : CertificatesHandler {

    override fun handleRegenerate(
        credentialUuid: String,
        request: CertificateRegenerateRequest
    ): CredentialView {

        val existingCredentialVersion = certificateService
                .findByCredentialUuid(credentialUuid)

        val generateRequest = generationRequestGenerator
                .createGenerateRequest(existingCredentialVersion)
        val credentialValue = credentialGenerator
                .generate(generateRequest) as CertificateCredentialValue
        credentialValue.isTransitional = request.isTransitional

        val credentialVersion = permissionedCertificateService
                .save(
                        existingCredentialVersion,
                        credentialValue,
                        generateRequest
                ) as CertificateCredentialVersion

        auditRecord.setVersion(credentialVersion)

        return CertificateView(credentialVersion)
    }

    override fun handleGetAllRequest(): CertificateCredentialsView {
        val credentialList = permissionedCertificateService.getAll()
        val list = convertCertificateCredentialsToCertificateCredentialViews(credentialList)
        auditRecord.addAllCredentials(Lists.newArrayList<AuditableCredential>(credentialList))
        return CertificateCredentialsView(list)
    }

    override fun handleGetByNameRequest(name: String): CertificateCredentialsView {
        val credentialList = permissionedCertificateService.getByName(name)
        val list = convertCertificateCredentialsToCertificateCredentialViews(credentialList)
        return CertificateCredentialsView(list)
    }

    override fun handleGetAllVersionsRequest(uuidString: String, current: Boolean): List<CertificateView> {
        val uuid: UUID
        try {
            uuid = UUID.fromString(uuidString)
        } catch (e: IllegalArgumentException) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        val credentialList = permissionedCertificateService.getVersions(uuid, current)

        return credentialList.map { credential -> CertificateView(credential as CertificateCredentialVersion) }
    }

    override fun handleDeleteVersionRequest(certificateId: String, versionId: String): CertificateView {
        val deletedVersion = permissionedCertificateService
                .deleteVersion(UUID.fromString(certificateId), UUID.fromString(versionId))
        return CertificateView(deletedVersion)
    }

    override fun handleUpdateTransitionalVersion(
        certificateId: String,
        requestBody: UpdateTransitionalVersionRequest
    ): List<CertificateView> {
        var versionUUID: UUID? = null

        if (requestBody.versionUuid != null) {
            versionUUID = UUID.fromString(requestBody.versionUuid)
        }

        val credentialList: List<CredentialVersion>
        credentialList = permissionedCertificateService
                .updateTransitionalVersion(UUID.fromString(certificateId), versionUUID)

        return credentialList
                .map { credential -> CertificateView(credential as CertificateCredentialVersion) }
    }

    override fun handleCreateVersionsRequest(certificateId: String, requestBody: CreateVersionRequest): CertificateView {
        val certificateCredentialValue = requestBody.value
        certificateCredentialValue.isTransitional = requestBody.isTransitional
        val credentialVersion = permissionedCertificateService.set(
                UUID.fromString(certificateId),
                certificateCredentialValue
        )

        return CertificateView(credentialVersion)
    }

    private fun convertCertificateCredentialsToCertificateCredentialViews(certificateCredentialList: List<Credential>): List<CertificateCredentialView> {
        val list = certificateCredentialList.map { credential ->
            val certificateVersions = permissionedCertificateService.getVersions(credential.uuid!!, false) as List<CertificateCredentialVersion>

            val certificateVersionViews = certificateVersions.map { certificateVersion ->
                CertificateVersionView(
                    id = certificateVersion.uuid!!,
                    expiryDate = certificateVersion.expiryDate,
                    transitional = certificateVersion.isVersionTransitional
                )
            }

            CertificateCredentialView(credential.name, credential.uuid, certificateVersionViews)
        }
        return list
    }
}

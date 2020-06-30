package org.cloudfoundry.credhub.certificates

import com.google.common.collect.Lists
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.PermissionOperation.DELETE
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.audit.AuditableCredential
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.PermissionException
import org.cloudfoundry.credhub.generate.GenerationRequestGenerator
import org.cloudfoundry.credhub.generate.UniversalCredentialGenerator
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest
import org.cloudfoundry.credhub.requests.CreateVersionRequest
import org.cloudfoundry.credhub.requests.UpdateTransitionalVersionRequest
import org.cloudfoundry.credhub.services.DefaultCertificateService
import org.cloudfoundry.credhub.services.PermissionCheckingService
import org.cloudfoundry.credhub.views.CertificateCredentialView
import org.cloudfoundry.credhub.views.CertificateCredentialsView
import org.cloudfoundry.credhub.views.CertificateVersionView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service
import java.util.ArrayList
import java.util.UUID

@Profile("!remote")
@Service
class DefaultCertificatesHandler(
    private val certificateService: DefaultCertificateService,
    private val credentialGenerator: UniversalCredentialGenerator,
    private val generationRequestGenerator: GenerationRequestGenerator,
    private val auditRecord: CEFAuditRecord,
    private val permissionCheckingService: PermissionCheckingService,
    private val userContextHolder: UserContextHolder,
    @Value("\${security.authorization.acls.enabled}") private val enforcePermissions: Boolean,
    @Value("\${certificates.concatenate_cas:false}") var concatenateCas: Boolean
) : CertificatesHandler {

    override fun handleRegenerate(
        credentialUuid: String,
        request: CertificateRegenerateRequest
    ): CredentialView {

        checkPermissionsByUuid(credentialUuid, WRITE)

        val existingCredentialVersion = certificateService
            .findByCredentialUuid(credentialUuid)

        val generateRequest = generationRequestGenerator
            .createGenerateRequest(existingCredentialVersion)
        generateRequest.metadata = request.metadata
        val credentialValue = credentialGenerator
            .generate(generateRequest) as CertificateCredentialValue

        credentialValue.transitional = request.isTransitional

        val credentialVersion = certificateService
            .save(
                existingCredentialVersion,
                credentialValue,
                generateRequest
            ) as CertificateCredentialVersion

        auditRecord.setVersion(credentialVersion)

        return CertificateView(credentialVersion, concatenateCas)
    }

    override fun handleGetAllRequest(): CertificateCredentialsView {
        val credentialList = filterPermissions(certificateService.getAll())
        val list = convertCertificateCredentialsToCertificateCredentialViews(credentialList, true)

        auditRecord.addAllCredentials(Lists.newArrayList<AuditableCredential>(credentialList))

        return CertificateCredentialsView(list)
    }

    override fun handleGetByNameRequest(name: String): CertificateCredentialsView {
        checkPermissionsByName(name, READ)

        val credentialList = certificateService.getByName(name)
        val list = convertCertificateCredentialsToCertificateCredentialViews(credentialList, false)

        return CertificateCredentialsView(list)
    }

    override fun handleGetAllVersionsRequest(certificateId: String, current: Boolean): List<CertificateView> {

        val uuid: UUID
        try {
            uuid = UUID.fromString(certificateId)
        } catch (e: IllegalArgumentException) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        checkPermissionsByUuid(uuid.toString(), READ)
        val credentialList = certificateService.getVersions(uuid, current)

        return credentialList.map { credential -> CertificateView(credential as CertificateCredentialVersion, concatenateCas) }
    }

    override fun handleDeleteVersionRequest(certificateId: String, versionId: String): CertificateView {
        checkPermissionsByUuid(certificateId, DELETE)

        val deletedVersion = certificateService
            .deleteVersion(UUID.fromString(certificateId), UUID.fromString(versionId))
        return CertificateView(deletedVersion)
    }

    override fun handleUpdateTransitionalVersion(
        certificateId: String,
        requestBody: UpdateTransitionalVersionRequest
    ): List<CertificateView> {
        checkPermissionsByUuid(certificateId, WRITE)
        var versionUUID: UUID? = null
        val certificateUUID: UUID = UUID.fromString(certificateId)

        if (requestBody.versionUuid != null) {
            versionUUID = if (requestBody.versionUuid == "latest") {
                certificateService.getAllValidVersions(certificateUUID).getOrNull(0)?.uuid
            } else {
                UUID.fromString(requestBody.versionUuid)
            }
        }

        val credentialList: List<CredentialVersion>
        credentialList = certificateService
            .updateTransitionalVersion(certificateUUID, versionUUID)

        return credentialList
            .map { credential -> CertificateView(credential as CertificateCredentialVersion) }
    }

    override fun handleCreateVersionsRequest(certificateId: String, requestBody: CreateVersionRequest): CertificateView {
        checkPermissionsByUuid(certificateId, WRITE)

        val certificateCredentialValue = requestBody.value
        certificateCredentialValue?.transitional = requestBody.isTransitional
        val credentialVersion = certificateService.set(
            UUID.fromString(certificateId),
            certificateCredentialValue
        )

        return CertificateView(credentialVersion)
    }

    private fun convertCertificateCredentialsToCertificateCredentialViews(certificateCredentialList: List<Credential>, getAllRequest: Boolean): List<CertificateCredentialView> {
        val names = certificateCredentialList.map { it.name!! }
        val certificates = certificateService.findAllValidMetadata(names)
        val caMapping = mutableMapOf<String, MutableList<String>>()

        if (getAllRequest) {
            certificates.forEach { certificateMetadata ->
                if (certificateMetadata.caName != null) {
                    val caName = certificateMetadata.caName

                    if (!caMapping.containsKey(caName)) {
                        caMapping[caName!!] = mutableListOf()
                    }

                    if (certificateMetadata.name != caName) {
                        caMapping.getValue(caName!!).add(certificateMetadata.name!!)
                    }
                }
            }
        }

        return certificates.map { certificateMetadata ->
            val certificateVersionViews = certificateMetadata.versions?.map { certificateVersion ->
                CertificateVersionView(certificateVersion)
            }?.toMutableList()
            val signedBy = certificateMetadata.caName ?: ""
            val signedCertificates: List<String>
            if (getAllRequest) {
                signedCertificates = caMapping.getOrDefault(certificateMetadata.name, mutableListOf())
            } else {
                signedCertificates = certificateService.findSignedCertificates(certificateMetadata.name!!)
            }
            CertificateCredentialView(
                certificateMetadata.name,
                certificateMetadata.id,
                certificateVersionViews,
                signedBy,
                signedCertificates
            )
        }
    }

    private fun checkPermissionsByName(name: String, permissionOperation: PermissionOperation) {
        if (!enforcePermissions) return

        if (!permissionCheckingService.hasPermission(
            userContextHolder.userContext?.actor!!,
            name,
            permissionOperation
        )
        ) {
            if (permissionOperation == WRITE) {
                throw PermissionException(ErrorMessages.Credential.INVALID_ACCESS)
            } else {
                throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
            }
        }
    }

    private fun checkPermissionsByUuid(uuid: String, permissionOperation: PermissionOperation) {
        if (!enforcePermissions) return

        val certificate = certificateService.findByCredentialUuid(uuid)

        if (!permissionCheckingService.hasPermission(
            userContextHolder.userContext?.actor!!,
            certificate.name!!,
            permissionOperation
        )
        ) {
            if (permissionOperation == WRITE) {
                throw PermissionException(ErrorMessages.Credential.INVALID_ACCESS)
            } else {
                throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
            }
        }
    }

    private fun filterPermissions(unfilteredCredentials: List<Credential>): List<Credential> {
        if (!enforcePermissions) {
            return unfilteredCredentials
        }
        val actor = userContextHolder.userContext?.actor
        val paths = permissionCheckingService.findAllPathsByActor(actor.toString())

        if (paths.contains("/*")) return unfilteredCredentials
        if (paths.isEmpty()) return ArrayList()

        val filteredCredentials = ArrayList<Credential>()

        for (credential in unfilteredCredentials) {
            val credentialName = credential.name
            if (paths.contains(credentialName)) {
                filteredCredentials.add(credential)
            }

            val result = ArrayList<String>()

            for (i in 1 until credentialName!!.length) {
                if (credentialName[i] == '/') {
                    result.add(credentialName.substring(0, i) + "/*")
                }
            }

            for (credentialPath in result) {
                if (paths.contains(credentialPath)) {
                    filteredCredentials.add(credential)
                    break
                }
            }
        }
        return filteredCredentials
    }
}

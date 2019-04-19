package org.cloudfoundry.credhub.permissions

import com.google.common.collect.Lists
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.audit.AuditableCredentialVersion
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.data.CertificateDataService
import org.cloudfoundry.credhub.data.CertificateVersionDataService
import org.cloudfoundry.credhub.domain.CertificateCredentialFactory
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.services.CredentialVersionDataService
import org.cloudfoundry.credhub.services.PermissionCheckingService
import org.cloudfoundry.credhub.services.PermissionedCredentialService
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

@Service
@Transactional
class PermissionedCertificateService(
    private val permissionedCredentialService: PermissionedCredentialService,
    private val certificateDataService: CertificateDataService,
    private val permissionCheckingService: PermissionCheckingService,
    private val userContextHolder: UserContextHolder,
    private val certificateVersionDataService: CertificateVersionDataService,
    private val certificateCredentialFactory: CertificateCredentialFactory,
    private val credentialVersionDataService: CredentialVersionDataService,
    private val auditRecord: CEFAuditRecord,
    @Value("\${certificates.concatenate_cas:false}") var concatenateCas: Boolean
) {

    fun save(
        existingCredentialVersion: CredentialVersion,
        credentialValue: CertificateCredentialValue,
        generateRequest: BaseCredentialGenerateRequest
    ): CredentialVersion {
        generateRequest.type = "certificate"
        if (credentialValue.isTransitional) {
            validateNoTransitionalVersionsAlreadyExist(generateRequest.name)
        }
        return permissionedCredentialService
            .save(
                existingCredentialVersion,
                credentialValue,
                generateRequest
            )
    }

    fun getAll(): List<Credential> {
        val allCertificates = certificateDataService.findAll()

        return allCertificates.filter { credential ->
            permissionCheckingService.hasPermission(
                userContextHolder.userContext.actor!!,
                credential.name!!,
                PermissionOperation.READ
            )
        }
    }

    fun getByName(name: String): List<Credential> {
        val certificate = certificateDataService.findByName(name)
            ?: throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)

        failForInvalidAccess(
            userContextHolder.userContext.actor!!,
            certificate.name!!,
            PermissionOperation.READ
        )

        return listOf(certificate)
    }

    fun getVersions(uuid: UUID, current: Boolean): List<CredentialVersion> {
        val list: List<CredentialVersion>?
        val name: String?

        try {
            if (current) {
                val credential = findCertificateCredential(uuid)
                name = credential.name
                list = certificateVersionDataService.findActiveWithTransitional(name!!)
            } else {
                list = certificateVersionDataService.findAllVersions(uuid)
                name = if (!list.isEmpty()) list[0].name else null
            }
        } catch (e: IllegalArgumentException) {
            throw InvalidQueryParameterException(ErrorMessages.BAD_REQUEST, "uuid")
        }

        if (list!!.isEmpty() || name == null) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        failForInvalidAccess(
            userContextHolder.userContext.actor!!,
            name,
            PermissionOperation.READ
        )

        return concatenateCas(list)
    }

    fun getAllValidVersions(uuid: UUID): List<CredentialVersion> {
        val list: List<CredentialVersion>?
        val name: String?

        try {
            list = certificateVersionDataService.findAllValidVersions(uuid)
            name = if (!list.isEmpty()) list[0].name else null
        } catch (e: IllegalArgumentException) {
            throw InvalidQueryParameterException(ErrorMessages.BAD_REQUEST, "uuid")
        }

        if (list.isEmpty()) {
            return emptyList()
        }

        if (name == null) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        failForInvalidAccess(
            userContextHolder.userContext.actor!!,
            name,
            PermissionOperation.READ
        )

        return list
    }

    fun findSignedCertificates(caName: String): List<String> {
        return permissionedCredentialService.findAllCertificateCredentialsByCaName(caName)
    }

    fun updateTransitionalVersion(certificateUuid: UUID, newTransitionalVersionUuid: UUID?): List<CredentialVersion> {
        val credential = findCertificateCredential(certificateUuid)

        val name = credential.name

        failForInvalidAccess(
            userContextHolder.userContext.actor!!,
            name!!,
            PermissionOperation.WRITE
        )

        certificateVersionDataService.unsetTransitionalVersion(certificateUuid)

        if (newTransitionalVersionUuid != null) {
            val version = certificateVersionDataService.findVersion(newTransitionalVersionUuid)

            if (versionDoesNotBelongToCertificate(credential, version)) {
                throw ParameterizedValidationException(ErrorMessages.Credential.MISMATCHED_CREDENTIAL_AND_VERSION)
            }
            certificateVersionDataService.setTransitionalVersion(newTransitionalVersionUuid)
        }

        val credentialVersions = certificateVersionDataService.findActiveWithTransitional(name)
        auditRecord.addAllVersions(Lists.newArrayList<AuditableCredentialVersion>(credentialVersions!!))

        return credentialVersions
    }

    fun deleteVersion(certificateUuid: UUID, versionUuid: UUID): CertificateCredentialVersion {
        val certificate = certificateDataService.findByUuid(certificateUuid)
            ?: throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)

        failForInvalidAccess(
            userContextHolder.userContext.actor!!,
            certificate.name!!,
            PermissionOperation.DELETE
        )

        val versionToDelete = certificateVersionDataService.findVersion(versionUuid)

        if (versionDoesNotBelongToCertificate(certificate, versionToDelete)) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        if (certificateHasOnlyOneVersion(certificateUuid)) {
            throw ParameterizedValidationException(ErrorMessages.Credential.CANNOT_DELETE_LAST_VERSION)
        }

        certificateVersionDataService.deleteVersion(versionUuid)
        return versionToDelete
    }

    operator fun set(certificateUuid: UUID, value: CertificateCredentialValue): CertificateCredentialVersion {
        val credential = findCertificateCredential(certificateUuid)

        failForInvalidAccess(
            userContextHolder.userContext.actor!!,
            credential.name!!,
            PermissionOperation.WRITE
        )

        if (value.isTransitional) {
            validateNoTransitionalVersionsAlreadyExist(credential.name)
        }

        val certificateCredentialVersion = certificateCredentialFactory
            .makeNewCredentialVersion(credential, value)

        return credentialVersionDataService.save(certificateCredentialVersion) as CertificateCredentialVersion
    }

    private fun concatenateCas(credentialVersions: List<CredentialVersion>): List<CredentialVersion> {
        if (!concatenateCas) return credentialVersions
        return credentialVersions.map {
            val certificateCredentialVersion = it as CertificateCredentialVersion
            if (certificateCredentialVersion.caName != null) {
                val findActiveWithTransitional = credentialVersionDataService.findActiveByName(certificateCredentialVersion.caName)
                certificateCredentialVersion.ca = findActiveWithTransitional!!.joinToString("\n") { credentialVersion ->
                    credentialVersion as CertificateCredentialVersion
                    credentialVersion.certificate.trim()
                }
            }
            certificateCredentialVersion
        }
    }

    private fun failForInvalidAccess(
        actor: String,
        credentialName: String,
        permissionOperation: PermissionOperation
    ) {
        val hasPermission = permissionCheckingService.hasPermission(
            actor,
            credentialName,
            permissionOperation
        )

        if (!hasPermission) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
    }

    private fun versionDoesNotBelongToCertificate(certificate: Credential, version: CertificateCredentialVersion?): Boolean {
        return version == null || certificate.uuid != version.credential.uuid
    }

    private fun certificateHasOnlyOneVersion(certificateUuid: UUID): Boolean {
        return certificateVersionDataService.findAllVersions(certificateUuid).size == 1
    }

    private fun findCertificateCredential(certificateUuid: UUID): Credential {
        return certificateDataService.findByUuid(certificateUuid)
            ?: throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
    }

    private fun validateNoTransitionalVersionsAlreadyExist(name: String?) {
        val credentialVersions = permissionedCredentialService
            .findAllByName(name!!)

        val transitionalVersionsAlreadyExist = credentialVersions.stream()
            .map { version -> version as CertificateCredentialVersion }
            .anyMatch { version -> version.isVersionTransitional }

        if (transitionalVersionsAlreadyExist) {
            throw ParameterizedValidationException(ErrorMessages.TOO_MANY_TRANSITIONAL_VERSIONS)
        }
    }
}

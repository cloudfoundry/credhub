package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation.DELETE
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.entities.GetCredentialById
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.constants.CredentialWriteMode
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.data.CertificateAuthorityService
import org.cloudfoundry.credhub.data.CredentialDataService
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialFactory
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.exceptions.PermissionException
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.requests.BaseCredentialRequest
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.views.FindCredentialResult
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class DefaultPermissionedCredentialService(
    private val credentialVersionDataService: CredentialVersionDataService,
    private val credentialFactory: CredentialFactory,
    private val permissionCheckingService: PermissionCheckingService,
    private val certificateAuthorityService: CertificateAuthorityService,
    private val userContextHolder: UserContextHolder,
    private val credentialDataService: CredentialDataService,
    private val auditRecord: CEFAuditRecord,
    @Value("\${certificates.concatenate_cas:false}") var concatenateCas: Boolean
)
    : PermissionedCredentialService {

    override fun save(
        existingCredentialVersion: CredentialVersion?,
        credentialValue: CredentialValue?,
        generateRequest: BaseCredentialRequest
    ): CredentialVersion {
        val shouldWriteNewCredential = shouldWriteNewCredential(existingCredentialVersion, generateRequest)

        validateCredentialSave(generateRequest.name, generateRequest.type, existingCredentialVersion)

        return if (!shouldWriteNewCredential) {
            existingCredentialVersion!!
        } else makeAndSaveNewCredential(existingCredentialVersion, credentialValue, generateRequest)
    }

    override fun delete(credentialName: String): Boolean {
        if (!permissionCheckingService.hasPermission(userContextHolder.userContext.actor!!, credentialName, DELETE)) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
        return credentialVersionDataService.delete(credentialName)
    }

    override fun findAllByName(credentialName: String): List<CredentialVersion> {
        if (!permissionCheckingService.hasPermission(userContextHolder.userContext.actor!!, credentialName, READ)) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        val credentialList = credentialVersionDataService.findAllByName(credentialName)

        for (credentialVersion in credentialList) {
            auditRecord.addVersion(credentialVersion)
            auditRecord.addResource(credentialVersion.credential)
        }

        return concatenateCas(credentialList)
    }

    override fun findNByName(credentialName: String, numberOfVersions: Int): List<CredentialVersion> {
        if (numberOfVersions < 0) {
            throw InvalidQueryParameterException(ErrorMessages.INVALID_QUERY_PARAMETER, "versions")
        }

        if (!permissionCheckingService.hasPermission(userContextHolder.userContext.actor!!, credentialName, READ)) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        val credentialList = credentialVersionDataService.findNByName(credentialName, numberOfVersions)

        return concatenateCas(credentialList)
    }

    override fun findActiveByName(credentialName: String): List<CredentialVersion> {
        if (!permissionCheckingService.hasPermission(userContextHolder.userContext.actor!!, credentialName, READ)) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
        val credentialList = credentialVersionDataService.findActiveByName(credentialName)

        for (credentialVersion in credentialList!!) {
            auditRecord.addVersion(credentialVersion)
            auditRecord.addResource(credentialVersion.credential)
        }

        return concatenateCas(credentialList)
    }

    override fun findByUuid(credentialUUID: UUID): Credential {
        val credential = credentialDataService.findByUUID(credentialUUID)
            ?: throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)

        if (!permissionCheckingService.hasPermission(userContextHolder.userContext.actor!!, credential.name!!, READ)) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
        return credential
    }

    override fun findVersionByUuid(credentialUUID: String): CredentialVersion {
        val credentialVersion = credentialVersionDataService.findByUuid(credentialUUID)

        auditRecord.requestDetails = GetCredentialById(credentialUUID)

        if (credentialVersion != null) {
            auditRecord.setVersion(credentialVersion)
            auditRecord.setResource(credentialVersion.credential)
        } else {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        val credentialName = credentialVersion.name

        if (!permissionCheckingService.hasPermission(userContextHolder.userContext.actor!!, credentialName, READ)) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        val findByUuid = credentialVersionDataService.findByUuid(credentialUUID)!!
        return concatenateCas(listOf(findByUuid))[0]
    }

    override fun findAllCertificateCredentialsByCaName(caName: String): List<String> {
        if (!permissionCheckingService.hasPermission(userContextHolder.userContext.actor!!, caName, READ)) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        return credentialVersionDataService.findAllCertificateCredentialsByCaName(caName)
    }

    fun findStartingWithPath(path: String): List<FindCredentialResult> {
        return findStartingWithPath(path, "")
    }

    override fun findStartingWithPath(path: String, expiresWithinDays: String): List<FindCredentialResult> {
        return credentialVersionDataService.findStartingWithPath(path, expiresWithinDays)
    }

    override fun findContainingName(name: String, expiresWithinDays: String): List<FindCredentialResult> {
        return credentialVersionDataService.findContainingName(name, expiresWithinDays)
    }

    override fun findMostRecent(credentialName: String): CredentialVersion? {
        return credentialVersionDataService.findMostRecent(credentialName)
    }

    private fun concatenateCas(credentialVersions: List<CredentialVersion>): List<CredentialVersion> {
        if (!concatenateCas) return credentialVersions
        return credentialVersions.map {
            val certificateCredentialVersion = it as? CertificateCredentialVersion ?: return credentialVersions
            if (certificateCredentialVersion.caName != null) {
                val findActiveWithTransitional = credentialVersionDataService.findActiveByName(certificateCredentialVersion.caName)
                certificateCredentialVersion.ca = findActiveWithTransitional?.joinToString("\n") { credentialVersion ->
                    credentialVersion as CertificateCredentialVersion
                    credentialVersion.certificate.trim()
                } ?: certificateCredentialVersion.ca
            }
            certificateCredentialVersion
        }
    }

    private fun makeAndSaveNewCredential(
        existingCredentialVersion: CredentialVersion?,
        credentialValue: CredentialValue?,
        request: BaseCredentialRequest
    ): CredentialVersion {
        val newVersion = credentialFactory.makeNewCredentialVersion(
            CredentialType.valueOf(request.type.toUpperCase()),
            request.name,
            credentialValue,
            existingCredentialVersion,
            request.generationParameters
        )
        return credentialVersionDataService.save(newVersion)
    }

    private fun shouldWriteNewCredential(
        existingCredentialVersion: CredentialVersion?,
        request: BaseCredentialRequest
    ): Boolean {
        if (request is BaseCredentialSetRequest<*>) {
            return true
        }

        if (existingCredentialVersion == null) {
            return true
        }

        if (request is BaseCredentialGenerateRequest) {

            if (request.mode != null && request.mode == CredentialWriteMode.NO_OVERWRITE) {
                return false
            }

            if (request.mode != null && request.mode == CredentialWriteMode.OVERWRITE) {
                return true
            }
        }

        if (existingCredentialVersion is CertificateCredentialVersion) {
            val certificateCredentialVersion = existingCredentialVersion as CertificateCredentialVersion?
            if (certificateCredentialVersion!!.caName != null) {
                val updatedCA = certificateCredentialVersion.ca != certificateAuthorityService.findActiveVersion(certificateCredentialVersion.caName).certificate
                if (updatedCA) {
                    return true
                }
            }
        }

        if (!existingCredentialVersion.matchesGenerationParameters(request.generationParameters)) {
            return true
        }

        val generateRequest = request as BaseCredentialGenerateRequest
        return generateRequest.isOverwrite
    }

    private fun validateCredentialSave(credentialName: String, type: String, existingCredentialVersion: CredentialVersion?) {
        verifyWritePermission(credentialName)

        if (existingCredentialVersion != null && existingCredentialVersion.credentialType != type) {
            throw ParameterizedValidationException(ErrorMessages.TYPE_MISMATCH)
        }
    }

    private fun verifyWritePermission(credentialName: String) {
        if (userContextHolder.userContext == null) {
            return
        }

        if (!permissionCheckingService.hasPermission(userContextHolder.userContext.actor, credentialName, WRITE)) {
            throw PermissionException(ErrorMessages.Credential.INVALID_ACCESS)
        }
    }
}

package org.cloudfoundry.credhub.services

import java.util.UUID
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.entities.GetCredentialById
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.constants.CredentialWriteMode
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialFactory
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.requests.BaseCredentialRequest
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.views.FindCredentialResult
import org.springframework.stereotype.Service

@Service
class DefaultCredentialService(
    private val credentialVersionDataService: CredentialVersionDataService,
    private val credentialFactory: CredentialFactory,
    private val certificateAuthorityService: CertificateAuthorityService,
    private val credentialDataService: CredentialDataService,
    private val auditRecord: CEFAuditRecord
) :
    CredentialService {

    override fun save(
        existingCredentialVersion: CredentialVersion?,
        credentialValue: CredentialValue?,
        generateRequest: BaseCredentialRequest
    ): CredentialVersion {
        validateCredentialSave(generateRequest.type, existingCredentialVersion)
        val shouldWriteNewCredential = shouldWriteNewCredential(existingCredentialVersion, generateRequest)

        return if (!shouldWriteNewCredential) {
            existingCredentialVersion!!
        } else makeAndSaveNewCredential(existingCredentialVersion, credentialValue, generateRequest)
    }

    override fun delete(credentialName: String): Boolean {
        return credentialVersionDataService.delete(credentialName)
    }

    override fun findAllByName(credentialName: String): List<CredentialVersion> {
        val credentialList = credentialVersionDataService.findAllByName(credentialName)

        for (credentialVersion in credentialList) {
            auditRecord.addVersion(credentialVersion)
            auditRecord.addResource(credentialVersion.credential)
        }

        return credentialList
    }

    override fun findNByName(credentialName: String, numberOfVersions: Int): List<CredentialVersion> {
        if (numberOfVersions < 0) {
            throw InvalidQueryParameterException(ErrorMessages.INVALID_QUERY_PARAMETER, "versions")
        }

        return credentialVersionDataService.findNByName(credentialName, numberOfVersions)
    }

    override fun findActiveByName(credentialName: String): List<CredentialVersion> {
        return credentialVersionDataService.findActiveByName(credentialName)!!
    }

    override fun findByUuid(credentialUUID: UUID): Credential {

        return credentialDataService.findByUUID(credentialUUID)
            ?: throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
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

        return listOf(credentialVersion)[0]
    }

    override fun findAllCertificateCredentialsByCaName(caName: String): List<String> {

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

            if (request.overwrite != null && !request.isOverwrite) {
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

    private fun validateCredentialSave(type: String, existingCredentialVersion: CredentialVersion?) {

        if (existingCredentialVersion != null && existingCredentialVersion.credentialType != type) {
            throw ParameterizedValidationException(ErrorMessages.TYPE_MISMATCH)
        }
    }
}

package org.cloudfoundry.credhub.services

import com.google.common.collect.Lists
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.audit.AuditableCredentialVersion
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialFactory
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CertificateMetadata
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

@Service
@Transactional
class DefaultCertificateService(
    private val credentialService: CredentialService,
    private val certificateDataService: CertificateDataService,
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
        if (credentialValue.transitional) {
            validateNoTransitionalVersionsAlreadyExist(generateRequest.name)
        }
        val version = credentialService
            .save(
                existingCredentialVersion,
                credentialValue,
                generateRequest
            ) as CertificateCredentialVersion

        if (version.isVersionTransitional) {
            createNewChildVersions(version.name!!)
        }
        return version
    }

    fun getAll(): List<Credential> {
        return certificateDataService.findAll()
    }

    fun getByName(name: String): List<Credential> {
        val certificate = certificateDataService.findByName(name)
            ?: throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)

        return listOf(certificate)
    }

    fun getVersions(uuid: UUID, current: Boolean): List<CredentialVersion> {
        val list: List<CredentialVersion>?
        val name: String?

        try {
            if (current) {
                val credential = findCertificateCredential(uuid)
                name = credential.name
                list = certificateVersionDataService.findBothActiveCertAndTransitionalCert(name!!)
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

        return list
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

        return list
    }

    fun findAllValidMetadata(names: List<String>): List<CertificateMetadata> {
        // This is a workaround for Postgres's limit of 32768 bind variables per query.
        // It would be preferable to retrieve available certs and metadata in a single DB query.
        val batchSize = 16384
        return names
                .chunked(batchSize)
                .flatMap { namesChunk ->
                    certificateDataService.findAllValidMetadata(namesChunk)
                }
    }

    fun findSignedCertificates(caName: String): List<String> {
        return credentialService.findAllCertificateCredentialsByCaName(caName)
    }

    fun updateTransitionalVersion(certificateUuid: UUID, newTransitionalVersionUuid: UUID?): List<CredentialVersion> {
        val credential = findCertificateCredential(certificateUuid)

        val name = credential.name

        certificateVersionDataService.unsetTransitionalVersion(certificateUuid)

        if (newTransitionalVersionUuid != null) {
            val version = certificateVersionDataService.findVersion(newTransitionalVersionUuid)

            if (versionDoesNotBelongToCertificate(credential, version)) {
                throw ParameterizedValidationException(ErrorMessages.Credential.MISMATCHED_CREDENTIAL_AND_VERSION)
            }
            certificateVersionDataService.setTransitionalVersion(newTransitionalVersionUuid)
        }

        val credentialVersions = certificateVersionDataService.findBothActiveCertAndTransitionalCert(name!!)
        auditRecord.addAllVersions(Lists.newArrayList<AuditableCredentialVersion>(credentialVersions!!))

        createNewChildVersions(name)

        return credentialVersions
    }

    fun deleteVersion(certificateUuid: UUID, versionUuid: UUID): CertificateCredentialVersion {
        val certificate = certificateDataService.findByUuid(certificateUuid)
            ?: throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)

        val versionToDelete = certificateVersionDataService.findVersion(versionUuid)

        if (versionDoesNotBelongToCertificate(certificate, versionToDelete)) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }

        if (certificateHasOnlyOneVersion(certificateUuid)) {
            throw ParameterizedValidationException(ErrorMessages.Credential.CANNOT_DELETE_LAST_VERSION)
        }

        certificateVersionDataService.deleteVersion(versionUuid)

        if (versionToDelete.isVersionTransitional) {
            createNewChildVersions(versionToDelete.name!!)
        }

        return versionToDelete
    }

    fun findByCredentialUuid(credentialUuid: String): CertificateCredentialVersion {
        return certificateVersionDataService.findByCredentialUUID(credentialUuid)
            as? CertificateCredentialVersion
            ?: throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
    }

    operator fun set(certificateUuid: UUID, value: CertificateCredentialValue?): CertificateCredentialVersion {
        val credential = findCertificateCredential(certificateUuid)

        if (value?.transitional!!) {
            validateNoTransitionalVersionsAlreadyExist(credential.name)
        }

        val certificateCredentialVersion = certificateCredentialFactory
            .makeNewCredentialVersion(credential, value)

        val version = credentialVersionDataService.save(certificateCredentialVersion) as CertificateCredentialVersion

        if (version.isVersionTransitional) {
            createNewChildVersions(version.name!!)
        }

        return version
    }

    private fun createNewChildVersions(parentCredentialName: String) {
        if (!concatenateCas) {
            return
        }

        val signedCertificates = findSignedCertificates(parentCredentialName)
        signedCertificates.forEach {
            val credentialVersion = credentialVersionDataService.findMostRecent(it) as? CertificateCredentialVersion
            val credential = credentialVersion?.credential

            val signingCa = credentialVersion?.ca
            var trustedCa: CertificateCredentialVersion? = null
            val activeWithTransitional = certificateVersionDataService.findBothActiveCertAndTransitionalCert(parentCredentialName)

            val caVersion = activeWithTransitional?.get(0) as CertificateCredentialVersion

            if (caVersion.certificate != signingCa) {
                if (activeWithTransitional.size == 2 || caVersion.isVersionTransitional) {
                    trustedCa = caVersion
                }
            } else if (activeWithTransitional.size == 2) {
                trustedCa = activeWithTransitional[1] as CertificateCredentialVersion
            }

            val value = CertificateCredentialValue(
                signingCa,
                credentialVersion?.certificate,
                credentialVersion?.privateKey,
                credentialVersion?.caName,
                credentialVersion?.isCertificateAuthority ?: false,
                credentialVersion?.isSelfSigned ?: false,
                credentialVersion?.generated,
                false
            )

            val newCredentialVersion = certificateCredentialFactory
                .makeNewCredentialVersion(credential!!, value)

            newCredentialVersion.trustedCa = trustedCa?.certificate

            credentialVersionDataService.save(newCredentialVersion)
        }
    }

    private fun versionDoesNotBelongToCertificate(certificate: Credential, version: CertificateCredentialVersion?): Boolean {
        return version == null || certificate.uuid != version.credential?.uuid
    }

    private fun certificateHasOnlyOneVersion(certificateUuid: UUID): Boolean {
        return certificateVersionDataService.findAllVersions(certificateUuid).size == 1
    }

    private fun findCertificateCredential(certificateUuid: UUID): Credential {
        return certificateDataService.findByUuid(certificateUuid)
            ?: throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
    }

    private fun validateNoTransitionalVersionsAlreadyExist(name: String?) {
        val credentialVersions = credentialService
            .findAllByName(name!!)

        val transitionalVersionsAlreadyExist = credentialVersions.stream()
            .map { version -> version as CertificateCredentialVersion }
            .anyMatch { version -> version.isVersionTransitional }

        if (transitionalVersionsAlreadyExist) {
            throw ParameterizedValidationException(ErrorMessages.TOO_MANY_TRANSITIONAL_VERSIONS)
        }
    }
}

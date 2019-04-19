package org.cloudfoundry.credhub.data

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialFactory
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.entity.CredentialVersionData
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository
import org.cloudfoundry.credhub.utils.CertificateReader
import org.springframework.stereotype.Service
import java.util.ArrayList
import java.util.UUID

@Service
class DefaultCertificateVersionDataService(
    private val credentialVersionRepository: CredentialVersionRepository,
    private val credentialFactory: CredentialFactory,
    private val credentialDataService: CredentialDataService
) : CertificateVersionDataService {

    override fun findActive(caName: String): CredentialVersion? {
        val credential = credentialDataService.find(caName)

        return if (credential == null) {
            null
        } else {
            credentialFactory.makeCredentialFromEntity(credentialVersionRepository
                .findLatestNonTransitionalCertificateVersion(credential.uuid))
        }
    }

    override fun findByCredentialUUID(uuid: String): CredentialVersion? {
        return credentialFactory.makeCredentialFromEntity(credentialVersionRepository
            .findLatestNonTransitionalCertificateVersion(UUID.fromString(uuid)))
    }

    override fun findActiveWithTransitional(certificateName: String): List<CredentialVersion>? {
        val result = ArrayList<CredentialVersion>()
        val credential = credentialDataService.find(certificateName)

        if (credential == null) {
            return null
        } else {
            val uuid = credential.uuid

            val active = credentialVersionRepository.findLatestNonTransitionalCertificateVersion(uuid)
            if (active != null) {
                result.add(credentialFactory.makeCredentialFromEntity(active))
            }

            val transitional = credentialVersionRepository.findTransitionalCertificateVersion(uuid)
            if (transitional != null) {
                result.add(credentialFactory.makeCredentialFromEntity(transitional))
            }
            return result
        }
    }

    override fun findAllVersions(uuid: UUID): List<CredentialVersion> {
        val credentialVersionDataList = credentialVersionRepository.findAllByCredentialUuidAndTypeOrderByVersionCreatedAtDesc(
            uuid, CertificateCredentialVersionData.CREDENTIAL_DATABASE_TYPE)

        return credentialFactory.makeCredentialsFromEntities(credentialVersionDataList)
    }

    override fun findAllValidVersions(uuid: UUID): List<CredentialVersion> {
        val credentialVersionDataList = credentialVersionRepository.findAllByCredentialUuidAndTypeOrderByVersionCreatedAtDesc(
            uuid, CertificateCredentialVersionData.CREDENTIAL_DATABASE_TYPE)

        val validCredentialVersionDataList = ArrayList<CredentialVersionData<*>>()
        for (credentialVersionData in credentialVersionDataList) {
            if (isValidCertificate(credentialVersionData)) {
                validCredentialVersionDataList.add(credentialVersionData)
            }
        }

        return credentialFactory.makeCredentialsFromEntities(validCredentialVersionDataList)
    }

    override fun deleteVersion(versionUuid: UUID) {
        credentialVersionRepository.deleteById(versionUuid)
    }

    override fun findVersion(versionUuid: UUID): CertificateCredentialVersion {
        val credentialVersion = credentialVersionRepository.findOneByUuid(versionUuid)
        return credentialFactory.makeCredentialFromEntity(credentialVersion) as CertificateCredentialVersion
    }

    override fun setTransitionalVersion(newTransitionalVersionUuid: UUID) {
        val newTransitionalCertificate = credentialVersionRepository.findOneByUuid(newTransitionalVersionUuid) as CertificateCredentialVersionData
        newTransitionalCertificate.isTransitional = true
        credentialVersionRepository.save(newTransitionalCertificate)
    }

    override fun unsetTransitionalVersion(certificateUuid: UUID) {
        val transitionalCertificate = credentialVersionRepository.findTransitionalCertificateVersion(certificateUuid) as? CertificateCredentialVersionData
        if (transitionalCertificate != null) {
            transitionalCertificate.isTransitional = false
            credentialVersionRepository.save(transitionalCertificate)
        }
    }

    private fun isValidCertificate(credentialVersionData: CredentialVersionData<*>): Boolean {
        try {
            val cert = credentialVersionData as CertificateCredentialVersionData
            CertificateReader(cert.certificate)
        } catch (e: Exception) {
            return false
        }

        return true
    }
}

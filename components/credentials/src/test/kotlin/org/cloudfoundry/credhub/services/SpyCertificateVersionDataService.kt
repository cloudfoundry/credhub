package org.cloudfoundry.credhub.services

import java.util.UUID
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialVersion

class SpyCertificateVersionDataService : CertificateVersionDataService {
    override fun findActive(caName: String): CredentialVersion? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findByCredentialUUID(uuidString: String): CredentialVersion? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var findActiveWithTransitional__returns_credentialVersionList: List<CredentialVersion>
    lateinit var findActiveWithTransitional__calledWith_certificateName: String
    override fun findActiveWithTransitional(certificateName: String): List<CredentialVersion>? {
        findActiveWithTransitional__calledWith_certificateName = certificateName

        return findActiveWithTransitional__returns_credentialVersionList
    }

    override fun findAllVersions(uuid: UUID): List<CredentialVersion> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findAllValidVersions(uuid: UUID): List<CredentialVersion> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun deleteVersion(versionUuid: UUID) {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findVersion(versionUuid: UUID): CertificateCredentialVersion {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun setTransitionalVersion(newTransitionalVersionUuid: UUID) {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun unsetTransitionalVersion(certificateUuid: UUID) {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}

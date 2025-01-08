package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialVersion
import java.util.UUID

class SpyCertificateVersionDataService : CertificateVersionDataService {
    override fun findActive(caName: String): CredentialVersion? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findByCredentialUUID(uuidString: String): CredentialVersion? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var findactivewithtransitionalReturnsCredentialversionlist: List<CredentialVersion>
    lateinit var findactivewithtransitionalCalledwithCertificatename: String

    override fun findBothActiveCertAndTransitionalCert(certificateName: String): List<CredentialVersion>? {
        findactivewithtransitionalCalledwithCertificatename = certificateName

        return findactivewithtransitionalReturnsCredentialversionlist
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

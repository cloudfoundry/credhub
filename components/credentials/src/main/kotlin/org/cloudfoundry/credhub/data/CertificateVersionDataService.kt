package org.cloudfoundry.credhub.data

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialVersion
import java.util.UUID

interface CertificateVersionDataService {

    fun findActive(caName: String): CredentialVersion?

    fun findByCredentialUUID(uuid: String): CredentialVersion?

    fun findActiveWithTransitional(certificateName: String): List<CredentialVersion>?

    fun findAllVersions(uuid: UUID): List<CredentialVersion>

    fun findAllValidVersions(uuid: UUID): List<CredentialVersion>

    fun deleteVersion(versionUuid: UUID)

    fun findVersion(versionUuid: UUID): CertificateCredentialVersion

    fun setTransitionalVersion(newTransitionalVersionUuid: UUID)

    fun unsetTransitionalVersion(certificateUuid: UUID)
}

package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.CredentialVersionData
import org.cloudfoundry.credhub.views.FindCredentialResult
import java.util.UUID

interface CredentialVersionDataService {

    fun save(credentialVersion: CredentialVersion): CredentialVersion

    fun save(credentialVersionData: CredentialVersionData<*>): CredentialVersion

    fun findMostRecent(name: String): CredentialVersion?

    fun findByUuid(uuid: String): CredentialVersion?

    fun findAllCertificateCredentialsByCaName(caName: String): List<String>

    fun findContainingName(name: String, expiresWithinDays: String = ""): List<FindCredentialResult>
    fun findContainingName(name: String): List<FindCredentialResult>

    fun findStartingWithPath(path: String, expiresWithinDays: String = ""): List<FindCredentialResult>
    fun findStartingWithPath(path: String): List<FindCredentialResult>

    fun delete(name: String): Boolean

    fun findAllByName(name: String): List<CredentialVersion>

    fun findNByName(name: String, numberOfVersions: Int): List<CredentialVersion>

    fun countByEncryptionKey(): Map<UUID, Long>

    fun findActiveByName(name: String): List<CredentialVersion>?

    fun count(): Long?

    fun countEncryptedWithKeyUuidIn(uuids: Collection<UUID>): Long?
}

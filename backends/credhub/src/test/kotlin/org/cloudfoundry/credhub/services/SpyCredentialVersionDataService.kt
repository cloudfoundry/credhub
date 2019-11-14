package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.CredentialVersionData
import org.cloudfoundry.credhub.views.FindCredentialResult
import java.util.UUID

class SpyCredentialVersionDataService : CredentialVersionDataService {

    override fun save(credentialVersion: CredentialVersion): CredentialVersion {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun save(credentialVersionData: CredentialVersionData<*>): CredentialVersion {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findMostRecent(name: String): CredentialVersion? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findByUuid(uuid: String): CredentialVersion? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findAllCertificateCredentialsByCaName(caName: String): List<String> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findContainingName(name: String, expiresWithinDays: String): List<FindCredentialResult> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findContainingName(name: String): List<FindCredentialResult> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findStartingWithPath(path: String, expiresWithinDays: String): List<FindCredentialResult> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findStartingWithPath(path: String): List<FindCredentialResult> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun delete(name: String): Boolean {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findAllByName(name: String): List<CredentialVersion> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findNByName(name: String, numberOfVersions: Int): List<CredentialVersion> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var countByEncryptionKey__returns_map: Map<UUID, Long>
    override fun countByEncryptionKey(): Map<UUID, Long> {
        return countByEncryptionKey__returns_map
    }

    override fun findActiveByName(name: String): List<CredentialVersion>? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun count(): Long? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun countEncryptedWithKeyUuidIn(uuids: Collection<UUID>): Long? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}

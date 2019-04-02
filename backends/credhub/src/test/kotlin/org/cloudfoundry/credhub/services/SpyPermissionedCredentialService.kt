package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.requests.BaseCredentialRequest
import org.cloudfoundry.credhub.views.FindCredentialResult
import java.util.UUID

class SpyPermissionedCredentialService : PermissionedCredentialService {

    override fun save(existingCredentialVersion: CredentialVersion?, credentialValue: CredentialValue?, generateRequest: BaseCredentialRequest): CredentialVersion {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun delete(credentialName: String): Boolean {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findAllByName(credentialName: String): List<CredentialVersion> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findNByName(credentialName: String, numberOfVersions: Int): List<CredentialVersion> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findActiveByName(credentialName: String): List<CredentialVersion> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findByUuid(credentialUUID: UUID): Credential {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findVersionByUuid(credentialUUID: String): CredentialVersion {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findAllCertificateCredentialsByCaName(caName: String): List<String> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    lateinit var findStartingWithPath__returns_findCredentialResultList: List<FindCredentialResult>
    lateinit var findStartingWithPath__calledWith_path: String
    lateinit var findStartingWithPath__calledWith_expiresWithinDays: String
    override fun findStartingWithPath(path: String, expiresWithinDays: String): List<FindCredentialResult> {
        findStartingWithPath__calledWith_path = path
        findStartingWithPath__calledWith_expiresWithinDays = expiresWithinDays

        return findStartingWithPath__returns_findCredentialResultList
    }

    lateinit var findContainingName__calledWith_name: String
    lateinit var findContainingName__calledWith_expiresWithinDays: String
    lateinit var findContainingName__returns_findCredentialResultList: List<FindCredentialResult>
    override fun findContainingName(name: String, expiresWithinDays: String): List<FindCredentialResult> {
        findContainingName__calledWith_name = name
        findContainingName__calledWith_expiresWithinDays = expiresWithinDays

        return findContainingName__returns_findCredentialResultList
    }

    override fun findMostRecent(credentialName: String): CredentialVersion? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }
}

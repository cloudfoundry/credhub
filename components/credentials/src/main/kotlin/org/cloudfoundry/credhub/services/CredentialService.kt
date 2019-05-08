package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.requests.BaseCredentialRequest
import org.cloudfoundry.credhub.views.FindCredentialResult
import java.util.UUID

interface CredentialService {

    fun save(
        existingCredentialVersion: CredentialVersion?,
        credentialValue: CredentialValue?,
        generateRequest: BaseCredentialRequest
    ): CredentialVersion

    fun delete(credentialName: String): Boolean

    fun findAllByName(credentialName: String): List<CredentialVersion>

    fun findNByName(credentialName: String, numberOfVersions: Int): List<CredentialVersion>

    fun findActiveByName(credentialName: String): List<CredentialVersion>

    fun findByUuid(credentialUUID: UUID): Credential

    fun findVersionByUuid(credentialUUID: String): CredentialVersion

    fun findAllCertificateCredentialsByCaName(caName: String): List<String>

    fun findStartingWithPath(path: String, expiresWithinDays: String = ""): List<FindCredentialResult>

    fun findContainingName(name: String, expiresWithinDays: String): List<FindCredentialResult>

    fun findMostRecent(credentialName: String): CredentialVersion?
}

package org.cloudfoundry.credhub.regenerate

import com.fasterxml.jackson.databind.JsonNode
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.entities.BulkRegenerateCredential
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.PermissionException
import org.cloudfoundry.credhub.generate.GenerationRequestGenerator
import org.cloudfoundry.credhub.generate.UniversalCredentialGenerator
import org.cloudfoundry.credhub.requests.CertificateGenerateRequest
import org.cloudfoundry.credhub.services.CredentialService
import org.cloudfoundry.credhub.services.PermissionCheckingService
import org.cloudfoundry.credhub.utils.CertificateReader
import org.cloudfoundry.credhub.views.BulkRegenerateResults
import org.cloudfoundry.credhub.views.CredentialView
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service
import java.util.TreeSet

@Service
@Profile("!remote")
class DefaultRegenerateHandler(
    private val credentialService: CredentialService,
    private val credentialGenerator: UniversalCredentialGenerator,
    private val generationRequestGenerator: GenerationRequestGenerator,
    private val auditRecord: CEFAuditRecord,
    private val permissionCheckingService: PermissionCheckingService,
    private val userContextHolder: UserContextHolder,
    @Value("\${security.authorization.acls.enabled}") private val enforcePermissions: Boolean,
    @Value("\${certificates.concatenate_cas:false}") private val concatenateCas: Boolean,
) : RegenerateHandler {
    override fun handleRegenerate(
        credentialName: String,
        credentialMetadata: JsonNode?,
    ): CredentialView {
        checkPermissionsByName(credentialName, WRITE)

        val existingCredentialVersion =
            credentialService.findMostRecent(credentialName)
                ?: throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        if (existingCredentialVersion.getCredentialType() == "certificate") {
            val caName = (existingCredentialVersion as CertificateCredentialVersion).caName
            if (caName != null) {
                checkPermissionsByName(caName, READ)
            }
        }
        val generateRequest =
            generationRequestGenerator
                .createGenerateRequest(existingCredentialVersion)
        generateRequest.metadata = credentialMetadata
        val credentialValue = credentialGenerator.generate(generateRequest)

        val credentialVersion =
            credentialService.save(
                existingCredentialVersion,
                credentialValue,
                generateRequest,
            )

        auditRecord.setVersion(credentialVersion)
        auditRecord.setResource(credentialVersion.credential)

        return CredentialView.fromEntity(credentialVersion, concatenateCas, true)
    }

    override fun handleBulkRegenerate(signerName: String): BulkRegenerateResults {
        auditRecord.requestDetails = BulkRegenerateCredential(signerName)

        verifyRegeneratePermissions(signerName)

        val results = BulkRegenerateResults()
        val certificateSet = TreeSet(String.CASE_INSENSITIVE_ORDER)

        certificateSet.addAll(regenerateCertificatesSignedByCA(signerName))
        results.setRegeneratedCredentials(certificateSet)
        return results
    }

    private fun verifyRegeneratePermissions(signerName: String) {
        if (!enforcePermissions) return

        checkPermissionsByName(signerName, READ)
        credentialService
            .findAllCertificateCredentialsByCaName(signerName)
            .forEach {
                checkPermissionsByName(it, WRITE)
                val mostRecent =
                    credentialService.findMostRecent(it)
                        as CertificateCredentialVersion
                val certificate = CertificateReader(mostRecent.certificate)
                if (certificate.isCa) {
                    verifyRegeneratePermissions(it)
                }
            }
    }

    private fun regenerateCertificatesSignedByCA(signerName: String): Collection<String> {
        val results = TreeSet(String.CASE_INSENSITIVE_ORDER)
        val certificateNames = TreeSet(String.CASE_INSENSITIVE_ORDER)

        certificateNames.addAll(credentialService.findAllCertificateCredentialsByCaName(signerName))
        certificateNames
            .stream()
            .map { name -> this.regenerateCertificateAndDirectChildren(name) }
            .forEach { results.addAll(it) }

        return results
    }

    private fun regenerateCertificateAndDirectChildren(credentialName: String): Set<String> {
        val results = TreeSet(String.CASE_INSENSITIVE_ORDER)
        val existingCredentialVersion = credentialService.findMostRecent(credentialName)
        val generateRequest =
            generationRequestGenerator
                .createGenerateRequest(existingCredentialVersion) as CertificateGenerateRequest
        val newCredentialValue = credentialGenerator.generate(generateRequest)

        auditRecord.addVersion(existingCredentialVersion)
        auditRecord.addResource(existingCredentialVersion!!.credential)

        val credentialVersion =
            credentialService.save(
                existingCredentialVersion,
                newCredentialValue,
                generateRequest,
            )
        results.add(credentialVersion.name)

        val generationParameters =
            generateRequest
                .generationParameters as CertificateGenerationParameters
        if (generationParameters.isCa) {
            results.addAll(this.regenerateCertificatesSignedByCA(generateRequest.name!!))
        }
        return results
    }

    private fun checkPermissionsByName(
        name: String,
        permissionOperation: PermissionOperation,
    ) {
        if (!enforcePermissions) return

        if (!permissionCheckingService.hasPermission(
                userContextHolder.userContext?.actor!!,
                name,
                permissionOperation,
            )
        ) {
            if (permissionOperation == WRITE) {
                throw PermissionException(ErrorMessages.Credential.INVALID_ACCESS)
            } else {
                throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
            }
        }
    }
}

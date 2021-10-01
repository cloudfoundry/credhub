package org.cloudfoundry.credhub.interpolation

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.domain.JsonCredentialVersion
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.exceptions.PermissionException
import org.cloudfoundry.credhub.services.CredentialService
import org.cloudfoundry.credhub.services.PermissionCheckingService
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service
import java.util.ArrayList

@Service
@Profile("!remote")
class DefaultInterpolationHandler(
    val credentialService: CredentialService,
    val auditRecord: CEFAuditRecord,
    private val permissionCheckingService: PermissionCheckingService,
    private val userContextHolder: UserContextHolder,
    @Value("\${security.authorization.acls.enabled}") private val enforcePermissions: Boolean
) : InterpolationHandler {

    override fun interpolateCredHubReferences(servicesMap: Map<String, Any>): Map<String, Any> {
        val updatedServicesMap = servicesMap.toMutableMap()
        for (entry in servicesMap) {
            val properties = entry.value as? ArrayList<*> ?: continue
            for ((index, property) in properties.withIndex()) {
                val propertyMap = property as? MutableMap<String, Any> ?: continue

                val credentials = propertyMap["credentials"] as? Map<*, *> ?: continue

                // Allow either snake_case or kebab-case
                val credhubRef = credentials["credhub_ref"] ?: credentials["credhub-ref"]
                val credhubRefString = credhubRef as? String ?: continue
                val credentialName = getCredentialNameFromRef(credhubRefString)

                checkPermissionsByName(credentialName, READ)
                val credentialVersions = credentialService.findNByName(credentialName, 1)
                if (credentialVersions.isEmpty()) {
                    throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
                }

                val credentialVersion = credentialVersions.get(0)

                auditRecord.addResource(credentialVersion.credential)
                auditRecord.addVersion(credentialVersion)

                val jsonCredentialVersion = credentialVersion as? JsonCredentialVersion ?: throw ParameterizedValidationException(
                    ErrorMessages.Interpolation.INVALID_TYPE,
                    credentialName
                )

                val updatedPropertiesMap = (updatedServicesMap[entry.key] as ArrayList<*>)[index] as MutableMap<String, Any>

                updatedPropertiesMap["credentials"] = jsonCredentialVersion.getValue() as Any
            }
        }
        return updatedServicesMap
    }

    private fun getCredentialNameFromRef(credhubRef: String): String {
        return credhubRef.replaceFirst("^\\(\\(".toRegex(), "").replaceFirst("\\)\\)$".toRegex(), "")
    }

    private fun checkPermissionsByName(name: String, permissionOperation: PermissionOperation) {
        if (!enforcePermissions) return

        if (!permissionCheckingService.hasPermission(
                userContextHolder.userContext?.actor!!,
                name,
                permissionOperation
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

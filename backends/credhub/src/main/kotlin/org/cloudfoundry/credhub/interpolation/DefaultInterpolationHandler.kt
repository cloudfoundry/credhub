package org.cloudfoundry.credhub.interpolation

import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.domain.JsonCredentialVersion
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.services.PermissionedCredentialService
import org.springframework.stereotype.Service
import java.util.ArrayList

@Service
class DefaultInterpolationHandler(
    val credentialService: PermissionedCredentialService,
    val auditRecord: CEFAuditRecord) : InterpolationHandler {


    override fun interpolateCredHubReferences(servicesMap: Map<String, Any>): Map<String, Any> {
        val updatedServicesMap = servicesMap.toMutableMap()
        for (entry in servicesMap) {
            val properties = entry.value as? ArrayList<*> ?: continue
            for ((index ,property)  in properties.withIndex()) {
                val propertyMap = property as? MutableMap<String, Any> ?: continue

                val credentials = propertyMap["credentials"] as? Map<*,*> ?: continue

                // Allow either snake_case or kebab-case
                val credhubRef = credentials["credhub_ref"] ?: credentials["credhub-ref"]
                val credhubRefString = credhubRef as? String ?: continue
                val credentialName = getCredentialNameFromRef(credhubRefString)

                val credentialVersions = credentialService.findNByName(credentialName, 1)
                if (credentialVersions.isEmpty()) {
                    throw EntryNotFoundException("error.credential.invalid_access")
                }

                val credentialVersion = credentialVersions.get(0)

                auditRecord.addResource(credentialVersion.credential)
                auditRecord.addVersion(credentialVersion)

                val jsonCredentialVersion = credentialVersion as? JsonCredentialVersion ?: throw ParameterizedValidationException("error.interpolation.invalid_type",
                    credentialName)

                val updatedPropertiesMap = (updatedServicesMap[entry.key] as ArrayList<*>)[index] as MutableMap<String,Any>

                updatedPropertiesMap["credentials"] = jsonCredentialVersion.value
            }

        }
        return updatedServicesMap

    }

    private fun getCredentialNameFromRef(credhubRef: String): String {
        return credhubRef.replaceFirst("^\\(\\(".toRegex(), "").replaceFirst("\\)\\)$".toRegex(), "")
    }

}


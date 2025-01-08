package org.cloudfoundry.credhub.keyusage

import org.cloudfoundry.credhub.services.CredentialVersionDataService
import org.cloudfoundry.credhub.services.EncryptionKeySet
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service

@Service
@Profile("!remote")
class DefaultKeyUsageHandler(
    val credentialVersionDataService: CredentialVersionDataService,
    val keySet: EncryptionKeySet,
) : KeyUsageHandler {
    override fun getKeyUsage(): Map<String, Long> {
        val countByEncryptionKey = credentialVersionDataService.countByEncryptionKey()
        val totalCredCount = countByEncryptionKey.values.sum()

        val activeKeyCreds = countByEncryptionKey.getOrDefault(keySet.active.uuid, 0L)

        val credsEncryptedByKnownKeys =
            countByEncryptionKey
                .filter {
                    keySet.uuids.contains(it.key)
                }.values
                .sum()

        val unknownKeyCreds = totalCredCount - credsEncryptedByKnownKeys
        val inactiveKeyCreds = totalCredCount - (activeKeyCreds + unknownKeyCreds)

        return mapOf("active_key" to activeKeyCreds, "inactive_keys" to inactiveKeyCreds, "unknown_keys" to unknownKeyCreds)
    }
}

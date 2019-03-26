package org.cloudfoundry.credhub.handlers

import org.assertj.core.api.Assertions.assertThat
import org.cloudfoundry.credhub.keyusage.DefaultKeyUsageHandler
import org.cloudfoundry.credhub.services.CredentialVersionDataService
import org.cloudfoundry.credhub.services.EncryptionKey
import org.cloudfoundry.credhub.services.EncryptionKeySet
import org.cloudfoundry.credhub.services.SpyCredentialVersionDataService
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito
import org.mockito.Mockito.mock
import java.util.*

class DefaultKeyUsageHandlerTest {

    lateinit var credentialVersionDataService: SpyCredentialVersionDataService
    lateinit var keySet: EncryptionKeySet
    lateinit var handler: DefaultKeyUsageHandler

    @Before
    fun beforeEach() {
        credentialVersionDataService = SpyCredentialVersionDataService()
        keySet = mock(EncryptionKeySet::class.java)

        handler = DefaultKeyUsageHandler(credentialVersionDataService, keySet)
    }

    @Test
    fun `keyUsage returns map of key usages`() {
        val uuid = UUID.randomUUID()
        val uuid2 = UUID.randomUUID()
        val uuid3 = UUID.randomUUID()
        credentialVersionDataService.countByEncryptionKey__returns_results = mapOf(uuid to 20L, uuid2 to 10L, uuid3 to 5L)

        val key = EncryptionKey(null, uuid, null, "some-encryption-key-name");
        val uuids = setOf(uuid, uuid2)
        Mockito.`when`(keySet.active).thenReturn(key)
        Mockito.`when`(keySet.uuids).thenReturn(uuids)

        val keyUsage = handler.getKeyUsage()
        assertThat(keyUsage["active_key"]).isEqualTo(20L)
        assertThat(keyUsage["inactive_keys"]).isEqualTo(10L)
        assertThat(keyUsage["unknown_keys"]).isEqualTo(5L)



    }
}

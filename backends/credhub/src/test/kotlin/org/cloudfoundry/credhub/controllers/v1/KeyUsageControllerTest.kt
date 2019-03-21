package org.cloudfoundry.credhub.controllers.v1

import org.cloudfoundry.credhub.keyusage.KeyUsageController
import org.cloudfoundry.credhub.services.CredentialVersionDataService
import org.cloudfoundry.credhub.services.InternalEncryptionService
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import org.springframework.http.MediaType
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultHandlers.print
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder
import java.security.Key
import java.util.*

@RunWith(SpringRunner::class)
class KeyUsageControllerTest {

    private lateinit var credentialVersionDataService: CredentialVersionDataService
    private lateinit var keySet: org.cloudfoundry.credhub.services.EncryptionKeySet
    private lateinit var mockMvc: MockMvc

    @Before
    fun beforeEach() {
        credentialVersionDataService = mock(CredentialVersionDataService::class.java)
        keySet = org.cloudfoundry.credhub.services.EncryptionKeySet()

        val keyUsageController = KeyUsageController(credentialVersionDataService,
            keySet)

        mockMvc = MockMvcBuilders
            .standaloneSetup(keyUsageController)
            .alwaysDo<StandaloneMockMvcBuilder>(print())
            .build()
    }

    @Test
    fun `GET key usages gets key distribution across active, inactive, and unknown encryption keys`() {
        val activeKey = UUID.randomUUID()
        val knownKey = UUID.randomUUID()
        val unknownKey = UUID.randomUUID()

        val countByEncryptionKey = HashMap<UUID, Long>()
        countByEncryptionKey[activeKey] = 200L
        countByEncryptionKey[knownKey] = 10L
        countByEncryptionKey[unknownKey] = 5L

        keySet.add(org.cloudfoundry.credhub.services.EncryptionKey(mock(InternalEncryptionService::class.java), activeKey, mock(Key::class.java), "key-name"))
        keySet.add(org.cloudfoundry.credhub.services.EncryptionKey(mock(InternalEncryptionService::class.java), knownKey, mock(Key::class.java), "key-name"))
        keySet.setActive(activeKey)
        `when`(credentialVersionDataService.countByEncryptionKey()).thenReturn(countByEncryptionKey)

        mockMvc.perform(get(KeyUsageController.ENDPOINT))
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.active_key").value(200))
            .andExpect(jsonPath("$.inactive_keys").value(10))
            .andExpect(jsonPath("$.unknown_keys").value(5))
    }
}

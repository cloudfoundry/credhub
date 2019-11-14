package org.cloudfoundry.credhub.controllers.v1.keyusage

import com.fasterxml.jackson.databind.ObjectMapper
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.keyusage.KeyUsageController
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.Security

class KeyUsageControllerTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    lateinit var mockMvc: MockMvc
    lateinit var keyUsageHandler: SpyKeyUsageHandler

    @Before
    fun setUp() {

            keyUsageHandler = SpyKeyUsageHandler()
            val keyUsageController = KeyUsageController(keyUsageHandler)

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(keyUsageController, restDocumentation)

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun GET__keyusage__returns_map() {
        // language=json
        val responseBody = """
            {
              "active_key": 10,
              "inactive_keys": 2,
              "unknown_keys": 1
            }
        """.trimIndent()
        val objectMapper = ObjectMapper()
        val map = objectMapper.readValue(responseBody, Map::class.java) as Map<String, Integer>
        val longMap = map.mapValues { it.value.toLong() }
        keyUsageHandler.getKeyUsage__returns_map = longMap

        val mvcResult = mockMvc.perform(
                get(KeyUsageController.ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .credHubAuthHeader()
                ).andExpect(status().isOk)
                .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andDo(
                        document(
                                CredHubRestDocs.DOCUMENT_IDENTIFIER
                        )
                ).andReturn()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, responseBody, true)
    }
}

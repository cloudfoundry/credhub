package org.cloudfoundry.credhub.integration.v1.regneration

import com.jayway.jsonpath.JsonPath
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.helpers.RequestHelper
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.ALL_PERMISSIONS_TOKEN
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultHandlers.print
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.context.WebApplicationContext

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test", "unit-test-permissions"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
@TestPropertySource(properties = ["certificates.concatenate_cas=true"])
class RegenerateEndpointConcatenateCasIntegrationTest {
    @Autowired
    private val webApplicationContext: WebApplicationContext? = null

    private val API_V1_REGENERATE_ENDPOINT = "/api/v1/regenerate"

    private lateinit var mockMvc: MockMvc

    @Before
    fun beforeEach() {
        mockMvc = MockMvcBuilders
            .webAppContextSetup(webApplicationContext!!)
            .apply<DefaultMockMvcBuilder>(SecurityMockMvcConfigurers.springSecurity())
            .build()
    }

    @Test
    @Throws(Exception::class)
    fun certificateRegeneration_withConcatenateCasEnabled_shouldConcatenateCas() {
        val caName = "test-ca"
        val certName = "testCert"
        val generatedCa = JsonPath.parse(RequestHelper.generateCa(mockMvc, caName, ALL_PERMISSIONS_TOKEN))
            .read<String>("$.value.ca")
        RequestHelper.generateCertificate(mockMvc, certName, caName, ALL_PERMISSIONS_TOKEN)
        val generatedCaUUID = RequestHelper.getCertificateId(mockMvc, caName)
        val regeneratedCa = JsonPath.parse(RequestHelper.regenerateCertificate(mockMvc, generatedCaUUID, true, ALL_PERMISSIONS_TOKEN))
            .read<String>("$.value.ca")

        val regenerateCertificateRequest = post(API_V1_REGENERATE_ENDPOINT)
            .header("Authorization", "Bearer $ALL_PERMISSIONS_TOKEN")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            // language=JSON
            .content("""{
                "name": "$certName"
            }""".trimIndent())

        this.mockMvc!!.perform(regenerateCertificateRequest)
            .andDo(print())
            .andExpect(status().is2xxSuccessful)
            .andExpect(jsonPath("$.value.ca").value(generatedCa + regeneratedCa))
    }
}

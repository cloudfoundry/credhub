package org.cloudfoundry.credhub.integration.v1.regneration

import com.jayway.jsonpath.JsonPath
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.helpers.RequestHelper
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.ALL_PERMISSIONS_TOKEN
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer
import org.cloudfoundry.credhub.utils.CertificateReader
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.hamcrest.core.IsEqual
import org.junit.Assert
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.Timeout
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.event.ContextRefreshedEvent
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

    @Autowired
    private val applicationContext: ApplicationContext? = null

    @Autowired
    private val applicationEventPublisher: ApplicationEventPublisher? = null

    private val API_V1_REGENERATE_ENDPOINT = "/api/v1/regenerate"

    private lateinit var mockMvc: MockMvc

    @get:Rule
    val globalTimeout: Timeout = Timeout.seconds(60)

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpAll() {
            BouncyCastleFipsConfigurer.configure()
        }
    }

    @Before
    fun beforeEach() {
        mockMvc = MockMvcBuilders
            .webAppContextSetup(webApplicationContext!!)
            .apply<DefaultMockMvcBuilder>(SecurityMockMvcConfigurers.springSecurity())
            .build()
        applicationContext?.let { ContextRefreshedEvent(it) }?.let { applicationEventPublisher?.publishEvent(it) }
    }

    @Test
    @Throws(Exception::class)
    fun certificateRegeneration_withConcatenateCasEnabled_shouldConcatenateCas() {
        val caName = "/test-ca"
        val certName = "/testCert"

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
            .content(
                """{
                "name": "$certName"
            }
                """.trimIndent()
            )

        this.mockMvc.perform(regenerateCertificateRequest)
            .andDo(print())
            .andExpect(status().is2xxSuccessful)
            .andExpect(jsonPath("$.value.ca").value(generatedCa + regeneratedCa))
    }

    @Test
    fun `regeneratingACertificate_whenAllowTransitionalParentToSignIsTrue_returnsTheGeneratedCertificate_signedByTheTransitionalParent`() {
        val caName = "/test-ca"
        val certificateName = "leafCertificate"

        val generateCaResponse = RequestHelper.generateCa(mockMvc, caName, ALL_PERMISSIONS_TOKEN)
        val caCertificateGenerated = JsonPath.parse(generateCaResponse)
            .read<String>("$.value.certificate")
        Assert.assertNotNull(caCertificateGenerated)

        val caCredentialUuid = RequestHelper.getCertificateId(mockMvc, caName)

        RequestHelper.generateCertificateCredential(
            mockMvc,
            certificateName,
            true,
            "leaf-cert",
            caName,
            ALL_PERMISSIONS_TOKEN
        )
        val regenerateCertificateResponse = RequestHelper.regenerateCertificate(mockMvc, caCredentialUuid, true, ALL_PERMISSIONS_TOKEN)
        val caCertificateRegenerated = JsonPath.parse(regenerateCertificateResponse)
            .read<String>("$.value.certificate")
        Assert.assertNotNull(caCertificateRegenerated)
        val caCertificateRegeneratedIsTransitional = JsonPath.parse(regenerateCertificateResponse)
            .read<Boolean>("$.transitional")
        Assert.assertTrue(caCertificateRegeneratedIsTransitional)

        val certCredentialUuid = RequestHelper.getCertificateId(mockMvc, certificateName)
        val regenerateLeafRequest = post("/api/v1/certificates/$certCredentialUuid/regenerate")
            .header("Authorization", "Bearer $ALL_PERMISSIONS_TOKEN")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"set_as_transitional\": false, \"allow_transitional_parent_to_sign\": true }")

        val response = this.mockMvc.perform(regenerateLeafRequest)
            .andExpect(status().isOk)
            .andReturn().response
            .contentAsString

        val leafCA = JsonPath.parse(response).read<String>("$.value.ca")
        Assert.assertThat<String>(leafCA, IsEqual.equalTo<String>(caCertificateRegenerated + caCertificateGenerated))
        val leafCert = JsonPath.parse(response).read<String>("$.value.certificate")
        val reader = CertificateReader(leafCert)
        Assert.assertTrue(reader.isSignedByCa(caCertificateRegenerated))
    }
}

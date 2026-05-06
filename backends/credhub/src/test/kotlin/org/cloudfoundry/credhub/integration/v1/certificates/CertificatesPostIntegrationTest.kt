package org.cloudfoundry.credhub.integration.v1.certificates

import com.jayway.jsonpath.JsonPath
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.helpers.RequestHelper.generateCa
import org.cloudfoundry.credhub.helpers.RequestHelper.generateCertificateCredential
import org.cloudfoundry.credhub.helpers.RequestHelper.getCertificateId
import org.cloudfoundry.credhub.helpers.RequestHelper.regenerateCertificate
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.ALL_PERMISSIONS_TOKEN
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer
import org.cloudfoundry.credhub.utils.CertificateReader
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.core.IsEqual.equalTo
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.context.WebApplicationContext
import java.util.concurrent.TimeUnit

private const val CA_NAME = "/test-ca"

@ExtendWith(SpringExtension::class)
@ActiveProfiles(value = ["unit-test", "unit-test-permissions"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
@TestPropertySource(properties = ["certificates.concatenate_cas=false"])
@Timeout(60, unit = TimeUnit.SECONDS)
class CertificatesPostIntegrationTest {
    @Autowired
    private val webApplicationContext: WebApplicationContext? = null

    private lateinit var mockMvc: MockMvc
    private var caCertificate: String? = null
    private var caCredentialUuid: String = ""

    companion object {
        @BeforeAll
        @JvmStatic
        fun setUpAll() {
            BouncyCastleFipsConfigurer.configure()
        }
    }

    @BeforeEach
    @Throws(Exception::class)
    fun beforeEach() {
        mockMvc =
            MockMvcBuilders
                .webAppContextSetup(webApplicationContext!!)
                .apply<DefaultMockMvcBuilder>(springSecurity())
                .build()
    }

    @Test
    fun `regeneratingACertificate whenConcatenateCasIsFalse returnsTheGeneratedCertificate withoutConcatenatedCas`() {
        val generateCaResponse = generateCa(mockMvc, CA_NAME, ALL_PERMISSIONS_TOKEN)
        caCertificate =
            JsonPath
                .parse(generateCaResponse)
                .read<String>("$.value.certificate")
        caCredentialUuid = getCertificateId(mockMvc, CA_NAME)
        assertNotNull(caCertificate)

        val certificateName = "leafCertificate"

        generateCertificateCredential(
            mockMvc,
            certificateName,
            true,
            "leaf-cert",
            CA_NAME,
            ALL_PERMISSIONS_TOKEN,
        )

        val certCredentialUuid = getCertificateId(mockMvc, certificateName)
        regenerateCertificate(mockMvc, caCredentialUuid, true, ALL_PERMISSIONS_TOKEN)
        val regenerateLeafRequest =
            post("/api/v1/certificates/$certCredentialUuid/regenerate")
                .header("Authorization", "Bearer $ALL_PERMISSIONS_TOKEN")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{\"set_as_transitional\":\"false\"}")

        val response =
            this.mockMvc
                .perform(regenerateLeafRequest)
                .andExpect(status().isOk)
                .andReturn()
                .response
                .contentAsString

        val leafCA = JsonPath.parse(response).read<String>("$.value.ca")
        assertThat<String>(leafCA, equalTo<String>(caCertificate!!))
    }

    @Test
    fun `regeneratingACertificate_whenAllowTransitionalParentToSignIsTrue_returnsTheGeneratedCertificate_signedByTheTransitionalParent`() {
        generateCa(mockMvc, CA_NAME, ALL_PERMISSIONS_TOKEN)

        caCredentialUuid = getCertificateId(mockMvc, CA_NAME)

        val certificateName = "leafCertificate"

        generateCertificateCredential(
            mockMvc,
            certificateName,
            true,
            "leaf-cert",
            CA_NAME,
            ALL_PERMISSIONS_TOKEN,
        )
        val regenerateCertificateResponse = regenerateCertificate(mockMvc, caCredentialUuid, true, ALL_PERMISSIONS_TOKEN)
        caCertificate =
            JsonPath
                .parse(regenerateCertificateResponse)
                .read<String>("$.value.certificate")
        assertNotNull(caCertificate)
        val caCertificateRegeneratedIsTransitional =
            JsonPath
                .parse(regenerateCertificateResponse)
                .read<Boolean>("$.transitional")
        assertTrue(caCertificateRegeneratedIsTransitional)

        val certCredentialUuid = getCertificateId(mockMvc, certificateName)
        val regenerateLeafRequest =
            post("/api/v1/certificates/$certCredentialUuid/regenerate")
                .header("Authorization", "Bearer $ALL_PERMISSIONS_TOKEN")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{\"set_as_transitional\": false, \"allow_transitional_parent_to_sign\": true }")

        val response =
            this.mockMvc
                .perform(regenerateLeafRequest)
                .andExpect(status().isOk)
                .andReturn()
                .response
                .contentAsString

        val leafCA = JsonPath.parse(response).read<String>("$.value.ca")
        assertThat<String>(leafCA, equalTo<String>(caCertificate!!))
        val leafCert = JsonPath.parse(response).read<String>("$.value.certificate")
        val reader = CertificateReader(leafCert)
        assertTrue(reader.isSignedByCa(caCertificate))
    }
}

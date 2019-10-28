package org.cloudfoundry.credhub.integration.v1.certificates

import com.jayway.jsonpath.JsonPath
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.cloudfoundry.credhub.helpers.RequestHelper.generateCa
import org.cloudfoundry.credhub.helpers.RequestHelper.generateCertificateCredential
import org.cloudfoundry.credhub.helpers.RequestHelper.getCertificateId
import org.cloudfoundry.credhub.helpers.RequestHelper.regenerateCertificate
import org.cloudfoundry.credhub.utils.AuthConstants.Companion.ALL_PERMISSIONS_TOKEN
import org.hamcrest.core.IsEqual.equalTo
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.context.WebApplicationContext

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test", "unit-test-permissions"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
@TestPropertySource(properties = ["certificates.concatenate_cas=false"])
class CertificatesPostIntegrationTest {

    private val CA_NAME = "/test-ca"

    @Autowired
    private val webApplicationContext: WebApplicationContext? = null

    private var mockMvc: MockMvc? = null
    private var caCertificate: String? = null
    private var caCredentialUuid: String? = null

    @Before
    @Throws(Exception::class)
    fun beforeEach() {
        mockMvc = MockMvcBuilders
            .webAppContextSetup(webApplicationContext!!)
            .apply<DefaultMockMvcBuilder>(springSecurity())
            .build()
    }

    @Test
    fun `regeneratingACertificate whenConcatenateCasIsFalse returnsTheGeneratedCertificate withoutConcatenatedCas`() {
        val generateCaResponse = generateCa(mockMvc, CA_NAME, ALL_PERMISSIONS_TOKEN)
        caCertificate = JsonPath.parse(generateCaResponse)
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
            ALL_PERMISSIONS_TOKEN
        )

        val certCredentialUuid = getCertificateId(mockMvc, certificateName)
        regenerateCertificate(mockMvc, caCredentialUuid, true, ALL_PERMISSIONS_TOKEN)
        val regenerateLeafRequest = post("/api/v1/certificates/$certCredentialUuid/regenerate")
            .header("Authorization", "Bearer $ALL_PERMISSIONS_TOKEN")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"set_as_transitional\":\"false\"}")

        val response = this.mockMvc!!.perform(regenerateLeafRequest)
            .andExpect(status().isOk)
            .andReturn().response
            .contentAsString

        val leafCA = JsonPath.parse(response).read<String>("$.value.ca")
        assertThat<String>(leafCA, equalTo<String>(caCertificate!!))
    }
}

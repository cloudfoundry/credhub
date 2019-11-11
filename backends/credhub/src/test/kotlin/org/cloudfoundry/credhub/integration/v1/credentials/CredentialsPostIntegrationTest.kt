package org.cloudfoundry.credhub.integration.v1.credentials

import java.time.Instant
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.TestHelper
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.services.CertificateAuthorityService
import org.cloudfoundry.credhub.util.CurrentTimeProvider
import org.cloudfoundry.credhub.utils.AuthConstants
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.cloudfoundry.credhub.utils.TestConstants
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.boot.test.mock.mockito.SpyBean
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.context.WebApplicationContext

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test", "unit-test-permissions"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
@TestPropertySource(properties = ["certificates.concatenate_cas=false"])
class CredentialsPostIntegrationTest {
    private val FROZEN_TIME = Instant.ofEpochSecond(1400011001L)

    @Autowired
    private val webApplicationContext: WebApplicationContext? = null

    @SpyBean
    private val certificateAuthorityService: CertificateAuthorityService? = null

    @MockBean
    private val mockCurrentTimeProvider: CurrentTimeProvider? = null

    private var mockMvc: MockMvc? = null

    @Before
    fun beforeEach() {
        val fakeTimeSetter = TestHelper.mockOutCurrentTimeProvider(mockCurrentTimeProvider!!)

        fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli())

        mockMvc = MockMvcBuilders
            .webAppContextSetup(webApplicationContext!!)
            .apply<DefaultMockMvcBuilder>(SecurityMockMvcConfigurers.springSecurity())
            .build()
    }

    @Test
    @Throws(Exception::class)
    fun generate_whenConcatenateCasIsFalse_DoesNOTReturnConcatenatedCas() {
        val caCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CA,
            TestConstants.TEST_PRIVATE_KEY,
            "caName",
            TestConstants.TEST_TRUSTED_CA,
            true,
            true,
            true,
            true
        )

        Mockito.doReturn(caCredentialValue).`when`<CertificateAuthorityService>(certificateAuthorityService).findActiveVersion("/myCA")

        val trustedCaCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_TRUSTED_CA,
            TestConstants.TEST_TRUSTED_CA,
            TestConstants.TEST_PRIVATE_KEY,
            "caName",
            true,
            true,
            true,
            true
        )

        Mockito.doReturn(trustedCaCredentialValue).`when`<CertificateAuthorityService>(certificateAuthorityService).findTransitionalVersion("/myCA")

        val request = MockMvcRequestBuilders.post("/api/v1/data")
            .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
            .content("""
                {
                  "name": "myCertificate",
                  "type": "certificate",
                  "parameters": {
                    "common_name": "myCertificate",
                    "ca":"myCA"
                  }
                 }
                """.trimIndent())
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)

        mockMvc!!.perform(request)
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andExpect(MockMvcResultMatchers.jsonPath("$.value.ca").value(TestConstants.TEST_CA))
    }
}

package org.cloudfoundry.credhub.integration.v1.certificates

import org.cloudfoundry.credhub.AuthConstants
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.DatabaseProfileResolver
import org.cloudfoundry.credhub.TestHelper
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.Encryptor
import org.cloudfoundry.credhub.services.DefaultCertificateService
import org.cloudfoundry.credhub.util.CurrentTimeProvider
import org.cloudfoundry.credhub.utils.TestConstants
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.doReturn
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.boot.test.mock.mockito.SpyBean
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.DefaultMockMvcBuilder
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.context.WebApplicationContext
import java.time.Instant
import java.util.UUID

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test", "unit-test-permissions"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
@TestPropertySource(properties = ["certificates.concatenate_cas=true"])
class CertificatesGetConcatenateCasIntegrationTest {
    private val FROZEN_TIME = Instant.ofEpochSecond(1400011001L)
    private val CREDENTIAL_NAME = "/my-namespace/controllerGetTest/credential-name"
    private val CREDENTIAL_VALUE = "test value"

    @Autowired
    private val webApplicationContext: WebApplicationContext? = null

    @SpyBean
    private val encryptor: Encryptor? = null

    @SpyBean
    private val certificateService: DefaultCertificateService? = null

    @MockBean
    private val mockCurrentTimeProvider: CurrentTimeProvider? = null

    private var mockMvc: MockMvc? = null

    @Before
    fun beforeEach() {
        val fakeTimeSetter = TestHelper.mockOutCurrentTimeProvider(mockCurrentTimeProvider!!)

        fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli())

        mockMvc = MockMvcBuilders
            .webAppContextSetup(webApplicationContext!!)
            .apply<DefaultMockMvcBuilder>(springSecurity())
            .build()
    }

    @Test
    @Throws(Exception::class)
    fun gettingAllCertificateVersions_whenConcatenateCasIsTrue_returnsTheCertificateVersions_withConcatenatedCas() {
        val uuid = UUID.randomUUID()
        val uuid2 = UUID.randomUUID()
        val certificateVersion1 = CertificateCredentialVersion(CREDENTIAL_NAME)
        certificateVersion1.setEncryptor(encryptor)
        certificateVersion1.uuid = uuid
        certificateVersion1.versionCreatedAt = FROZEN_TIME
        certificateVersion1.ca = TestConstants.TEST_CERTIFICATE
        certificateVersion1.caName = "/some-ca"
        certificateVersion1.certificate = TestConstants.TEST_CERTIFICATE
        certificateVersion1.credential.uuid = uuid
        certificateVersion1.trustedCa = TestConstants.OTHER_TEST_CERTIFICATE

        doReturn(CREDENTIAL_VALUE).`when`<Encryptor>(encryptor).decrypt(any())

        val certificateVersion2 = CertificateCredentialVersion(CREDENTIAL_NAME)
        certificateVersion2.certificate = TestConstants.OTHER_TEST_CERTIFICATE
        certificateVersion2.ca = TestConstants.TEST_CA
        certificateVersion2.setEncryptor(encryptor)
        certificateVersion2.uuid = uuid2
        certificateVersion2.credential.uuid = uuid2

        doReturn(listOf(certificateVersion1, certificateVersion2)).`when`<DefaultCertificateService>(certificateService).getVersions(uuid, false)
        doReturn(certificateVersion1).`when`<DefaultCertificateService>(certificateService).findByCredentialUuid(uuid.toString())

        val request = get("/api/v1/certificates/$uuid/versions")
            .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
            .accept(APPLICATION_JSON)

        mockMvc!!.perform(request)
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$[0].type").value("certificate"))
            .andExpect(jsonPath("$[0].value.certificate").value(TestConstants.TEST_CERTIFICATE))
            .andExpect(jsonPath("$[0].id").value(uuid.toString()))
            .andExpect(jsonPath("$[0].version_created_at").value(FROZEN_TIME.toString()))
            .andExpect(jsonPath("$[0].value.ca").value(TestConstants.TEST_CERTIFICATE + "\n" + TestConstants.OTHER_TEST_CERTIFICATE + "\n"))
            .andExpect(jsonPath("$[1].type").value("certificate"))
            .andExpect(jsonPath("$[1].value.certificate").value(TestConstants.OTHER_TEST_CERTIFICATE))
            .andExpect(jsonPath("$[1].value.ca").value(TestConstants.TEST_CA))
    }
}

package org.cloudfoundry.credhub.integration.v1.credentials

import java.time.Instant
import java.util.Arrays
import java.util.UUID
import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.TestHelper
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.domain.Encryptor
import org.cloudfoundry.credhub.services.CredentialVersionDataService
import org.cloudfoundry.credhub.util.CurrentTimeProvider
import org.cloudfoundry.credhub.utils.AuthConstants
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
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

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test", "unit-test-permissions"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
@TestPropertySource(properties = ["certificates.concatenate_cas=true"])
class CredentialsGetConcatenateCasIntegrationTest {
    private val FROZEN_TIME = Instant.ofEpochSecond(1400011001L)
    private val CREDENTIAL_NAME = "/my-namespace/controllerGetTest/credential-name"
    private val CREDENTIAL_VALUE = "test value"

    @Autowired
    private val webApplicationContext: WebApplicationContext? = null

    @SpyBean
    private val encryptor: Encryptor? = null

    @SpyBean
    private val credentialVersionDataService: CredentialVersionDataService? = null

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
    fun gettingCurrentVersionOfACertificateCredential_byName_whenConcatenateCasIsTrue_returnsTheCredential_withConcatenatedCas() {
        val uuid = UUID.randomUUID()
        val certificate = CertificateCredentialVersion(CREDENTIAL_NAME)
        certificate.setEncryptor(encryptor!!)
        certificate.uuid = uuid
        certificate.versionCreatedAt = FROZEN_TIME
        certificate.ca = TestConstants.TEST_CERTIFICATE
        certificate.caName = "/some-ca"
        certificate.certificate = TestConstants.TEST_CERTIFICATE
        certificate.credential?.uuid = uuid
        certificate.trustedCa = TestConstants.OTHER_TEST_CERTIFICATE

        doReturn(CREDENTIAL_VALUE).`when`<Encryptor>(encryptor).decrypt(any())

        doReturn(listOf(certificate)).`when`<CredentialVersionDataService>(credentialVersionDataService).findActiveByName(CREDENTIAL_NAME)

        val request = get("/api/v1/data?name=$CREDENTIAL_NAME&current=true")
            .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
            .accept(APPLICATION_JSON)

        mockMvc!!.perform(request)
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.data[0].type").value("certificate"))
            .andExpect(jsonPath("$.data[0].value.certificate").value(TestConstants.TEST_CERTIFICATE))
            .andExpect(jsonPath("$.data[0].id").value(uuid.toString()))
            .andExpect(jsonPath("$.data[0].version_created_at").value(FROZEN_TIME.toString()))
            .andExpect(jsonPath("$.data[0].value.ca").value(TestConstants.TEST_CERTIFICATE + "\n" + TestConstants.OTHER_TEST_CERTIFICATE + "\n"))
    }

    @Test
    @Throws(Exception::class)
    fun gettingNVersionsOfACertificateCredential_byName_whenConcatenateCasIsTrue_returnsTheCredential_withConcatenatedCas() {
        val uuid = UUID.randomUUID()
        val uuid2 = UUID.randomUUID()
        val certificateVersion1 = CertificateCredentialVersion(CREDENTIAL_NAME)
        certificateVersion1.setEncryptor(encryptor!!)
        certificateVersion1.uuid = uuid
        certificateVersion1.versionCreatedAt = FROZEN_TIME
        certificateVersion1.ca = TestConstants.TEST_CERTIFICATE
        certificateVersion1.caName = "/some-ca"
        certificateVersion1.certificate = TestConstants.TEST_CERTIFICATE
        certificateVersion1.credential?.uuid = uuid
        certificateVersion1.trustedCa = TestConstants.OTHER_TEST_CERTIFICATE

        doReturn(CREDENTIAL_VALUE).`when`<Encryptor>(encryptor).decrypt(any())

        val certificateVersion2 = CertificateCredentialVersion(CREDENTIAL_NAME)
        certificateVersion2.certificate = TestConstants.TEST_CA
        certificateVersion2.ca = TestConstants.TEST_CA
        certificateVersion2.setEncryptor(encryptor)
        certificateVersion2.uuid = uuid2
        certificateVersion2.credential?.uuid = uuid2
        certificateVersion2.versionCreatedAt = FROZEN_TIME
        val credentialVersionList = Arrays.asList<CredentialVersion>(certificateVersion1, certificateVersion2)

        doReturn(credentialVersionList).`when`<CredentialVersionDataService>(credentialVersionDataService).findNByName(CREDENTIAL_NAME, 2)

        val request = get("/api/v1/data?name=$CREDENTIAL_NAME&versions=2")
            .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
            .accept(APPLICATION_JSON)

        mockMvc!!.perform(request)
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.data[0].type").value("certificate"))
            .andExpect(jsonPath("$.data[0].value.certificate").value(TestConstants.TEST_CERTIFICATE))
            .andExpect(jsonPath("$.data[0].id").value(uuid.toString()))
            .andExpect(jsonPath("$.data[0].version_created_at").value(FROZEN_TIME.toString()))
            .andExpect(jsonPath("$.data[0].value.ca").value(TestConstants.TEST_CERTIFICATE + "\n" + TestConstants.OTHER_TEST_CERTIFICATE + "\n"))
            .andExpect(jsonPath("$.data[1].type").value("certificate"))
            .andExpect(jsonPath("$.data[1].value.certificate").value(TestConstants.TEST_CA))
            .andExpect(jsonPath("$.data[1].value.ca").value(TestConstants.TEST_CA))
    }

    @Test
    @Throws(Exception::class)
    fun gettingAllVersionsOfACertificateCredential_byName_whenConcatenateCasIsTrue_returnsTheCredential_withConcatenatedCas() {
        val uuid = UUID.randomUUID()
        val uuid2 = UUID.randomUUID()
        val certificateVersion1 = CertificateCredentialVersion(CREDENTIAL_NAME)
        certificateVersion1.setEncryptor(encryptor!!)
        certificateVersion1.uuid = uuid
        certificateVersion1.versionCreatedAt = FROZEN_TIME
        certificateVersion1.ca = TestConstants.TEST_CERTIFICATE
        certificateVersion1.caName = "/some-ca"
        certificateVersion1.certificate = TestConstants.TEST_CERTIFICATE
        certificateVersion1.credential?.uuid = uuid
        certificateVersion1.trustedCa = TestConstants.OTHER_TEST_CERTIFICATE

        doReturn(CREDENTIAL_VALUE).`when`<Encryptor>(encryptor).decrypt(any())

        val certificateVersion2 = CertificateCredentialVersion(CREDENTIAL_NAME)
        certificateVersion2.certificate = TestConstants.OTHER_TEST_CERTIFICATE
        certificateVersion2.ca = TestConstants.TEST_CA
        certificateVersion2.setEncryptor(encryptor)
        certificateVersion2.uuid = uuid2
        certificateVersion2.credential?.uuid = uuid2
        certificateVersion2.versionCreatedAt = FROZEN_TIME
        val credentialVersionList = Arrays.asList<CredentialVersion>(certificateVersion1, certificateVersion2)

        doReturn(credentialVersionList).`when`<CredentialVersionDataService>(credentialVersionDataService).findAllByName(CREDENTIAL_NAME)

        val request = get("/api/v1/data?name=$CREDENTIAL_NAME")
            .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
            .accept(APPLICATION_JSON)

        mockMvc!!.perform(request)
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.data[0].type").value("certificate"))
            .andExpect(jsonPath("$.data[0].value.certificate").value(TestConstants.TEST_CERTIFICATE))
            .andExpect(jsonPath("$.data[0].id").value(uuid.toString()))
            .andExpect(jsonPath("$.data[0].version_created_at").value(FROZEN_TIME.toString()))
            .andExpect(jsonPath("$.data[0].value.ca").value(TestConstants.TEST_CERTIFICATE + "\n" + TestConstants.OTHER_TEST_CERTIFICATE + "\n"))
            .andExpect(jsonPath("$.data[1].type").value("certificate"))
            .andExpect(jsonPath("$.data[1].value.certificate").value(TestConstants.OTHER_TEST_CERTIFICATE))
            .andExpect(jsonPath("$.data[1].value.ca").value(TestConstants.TEST_CA))
    }
}

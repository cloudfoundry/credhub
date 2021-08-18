package org.cloudfoundry.credhub.services

import com.google.common.collect.Lists.newArrayList
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.auth.UserContext
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.CredentialFactory
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.domain.Encryptor
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.requests.BaseCredentialRequest
import org.cloudfoundry.credhub.requests.GenerationParameters
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.StringGenerationParameters
import org.cloudfoundry.credhub.utils.TestConstants
import org.junit.Before
import org.junit.Test
import org.mockito.ArgumentMatchers
import org.mockito.Mock
import org.mockito.Mockito.`when`
import org.mockito.Mockito.any
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.mockito.MockitoAnnotations.initMocks
import java.util.Arrays
import java.util.UUID
import java.util.regex.Pattern

class DefaultCredentialServiceTest {

    @Mock
    private lateinit var credentialVersionDataService: CredentialVersionDataService

    @Mock
    private lateinit var permissionCheckingService: PermissionCheckingService

    @Mock
    private lateinit var encryptor: Encryptor

    @Mock
    private lateinit var credentialFactory: CredentialFactory

    @Mock
    private lateinit var certificateAuthorityService: DefaultCertificateAuthorityService

    @Mock
    private lateinit var credentialDataService: CredentialDataService

    @Mock
    private lateinit var auditRecord: CEFAuditRecord

    private lateinit var subject: DefaultCredentialService
    private lateinit var existingCredentialVersion: CredentialVersion
    private lateinit var existingCertificateVersion: CredentialVersion
    private lateinit var userContext: UserContext
    private lateinit var generationParameters: StringGenerationParameters
    private lateinit var credentialValue: CredentialValue
    private lateinit var accessControlEntries: MutableList<PermissionEntry>
    private val request = mock<BaseCredentialRequest>(BaseCredentialRequest::class.java)
    private lateinit var credential: Credential

    private lateinit var nonTransitionalCa: CertificateCredentialVersion
    private lateinit var transitionalCa: CertificateCredentialVersion
    private lateinit var certificate: CertificateCredentialVersion
    private lateinit var certUuid: UUID

    @Before
    fun setUp() {
        initMocks(this)

        userContext = mock<UserContext>(UserContext::class.java)
        val userContextHolder = UserContextHolder()
        userContextHolder.userContext = userContext

        this.subject = DefaultCredentialService(
            credentialVersionDataService,
            credentialFactory,
            certificateAuthorityService,
            credentialDataService,
            auditRecord
        )

        generationParameters = mock<StringGenerationParameters>(StringGenerationParameters::class.java)
        credentialValue = mock<CredentialValue>(CredentialValue::class.java)
        credential = Credential(CREDENTIAL_NAME)
        accessControlEntries = ArrayList()

        `when`<String>(userContext.actor).thenReturn(USER)

        existingCredentialVersion = PasswordCredentialVersion(CREDENTIAL_NAME)
        existingCredentialVersion.setEncryptor(encryptor)

        existingCertificateVersion = CertificateCredentialVersion(CREDENTIAL_NAME)

        `when`<Boolean>(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(true)
        `when`<Boolean>(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, WRITE))
            .thenReturn(true)

        `when`<Credential>(credentialDataService.findByUUID(CREDENTIAL_UUID))
            .thenReturn(credential)
        `when`<CredentialVersion>(credentialVersionDataService.findByUuid(VERSION_UUID_STRING))
            .thenReturn(existingCredentialVersion)

        `when`<String>(request.name).thenReturn(CREDENTIAL_NAME)
        `when`<GenerationParameters>(request.generationParameters).thenReturn(generationParameters)

        certUuid = UUID.randomUUID()
        nonTransitionalCa = mock(CertificateCredentialVersion::class.java)
        `when`(nonTransitionalCa.certificate)
            .thenReturn(TestConstants.TEST_CERTIFICATE)
        transitionalCa = mock(CertificateCredentialVersion::class.java)
        `when`(transitionalCa.certificate)
            .thenReturn(TestConstants.OTHER_TEST_CERTIFICATE)
        certificate = CertificateCredentialVersion("some-cert")
        certificate.caName = "testCa"
        certificate.credential?.uuid = certUuid
        certificate.uuid = certUuid
        certificate.ca = TestConstants.TEST_CERTIFICATE
        certificate.trustedCa = TestConstants.TEST_CA
        `when`<List<CredentialVersion>>(credentialVersionDataService.findActiveByName(certificate.caName!!))
            .thenReturn(Arrays.asList<CredentialVersion>(nonTransitionalCa, transitionalCa))
    }

    @Test
    fun save_whenGivenTypeAndExistingTypeDontMatch_throwsException() {
        `when`(request.type).thenReturn("user")
        `when`<CredentialVersion>(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion)

        Assertions.assertThatThrownBy {
            this.subject.save(existingCredentialVersion, credentialValue, request)
        }.isInstanceOf(ParameterizedValidationException::class.java)
    }

    @Test
    fun save_whenGivenTypeAndExistingTypeDontMatch_andExistingTypeIsCertificate_throwsException() {
        `when`(request.type).thenReturn("user")
        `when`<CredentialVersion>(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCertificateVersion)

        Assertions.assertThatThrownBy {
            this.subject.save(existingCertificateVersion, credentialValue, request)
        }.isInstanceOf(ParameterizedValidationException::class.java)
    }

    @Test
    fun getNCredentialVersions_whenTheNumberOfCredentialsIsNegative_throws() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(true)

        Assertions.assertThatThrownBy {
            this.subject.findNByName(CREDENTIAL_NAME, -1)
        }.isInstanceOf(InvalidQueryParameterException::class.java)
            .hasMessage(ErrorMessages.INVALID_QUERY_PARAMETER)
    }

    @Test
    fun getCredentialVersion_whenTheVersionDoesNotExist_throwsException() {
        `when`<CredentialVersion>(credentialVersionDataService.findByUuid(VERSION_UUID_STRING))
            .thenReturn(null)

        Assertions.assertThatThrownBy {
            this.subject.findVersionByUuid(VERSION_UUID_STRING)
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun findByUuid_whenNoMatchingCredentialExists_throwsEntryNotFound() {
        Assertions.assertThatThrownBy {
            this.subject.findByUuid(UUID.randomUUID())
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun save_whenWritingCredential_savesANewVersion() {
        `when`(request.type).thenReturn("password")
        `when`<CredentialVersion>(credentialVersionDataService.findMostRecent(request.name.toString())).thenReturn(null)
        val stringGenerationParameters = StringGenerationParameters()
        `when`<GenerationParameters>(request.generationParameters).thenReturn(stringGenerationParameters)

        val stringCredentialValue = StringCredentialValue("password")
        val passwordCredentialVersion = PasswordCredentialVersion(
            stringCredentialValue,
            request.generationParameters as StringGenerationParameters,
            encryptor
        )

        `when`<CredentialVersion>(
            credentialFactory.makeNewCredentialVersion(
                CredentialType.valueOf(request.type?.toUpperCase().toString()),
                request.name,
                stringCredentialValue,
                null,
                request.generationParameters,
                null
            )
        ).thenReturn(passwordCredentialVersion)

        this.subject.save(null, stringCredentialValue, request)

        verify(credentialVersionDataService).save(passwordCredentialVersion)
    }

    @Test
    fun findAllByName_addsToTheAuditRecord() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(true)

        val expectedCredentials = newArrayList<CredentialVersion>(existingCredentialVersion)
        `when`(credentialVersionDataService.findAllByName(CREDENTIAL_NAME))
            .thenReturn(expectedCredentials)

        this.subject.findAllByName(CREDENTIAL_NAME)

        verify(auditRecord, times(1)).addResource(ArgumentMatchers.any(Credential::class.java))
        verify(auditRecord, times(1)).addVersion(ArgumentMatchers.any(CredentialVersion::class.java))
    }

    @Test
    fun findVersionByUuid_addsToTheAuditRecord() {
        `when`<CredentialVersion>(credentialVersionDataService.findByUuid(CREDENTIAL_UUID.toString()))
            .thenReturn(existingCredentialVersion)

        this.subject.findVersionByUuid(CREDENTIAL_UUID.toString())

        verify(auditRecord, times(1)).setResource(ArgumentMatchers.any(Credential::class.java))
        verify(auditRecord, times(1)).setVersion(ArgumentMatchers.any(CredentialVersion::class.java))
    }

    @Test
    fun getCredentialVersion_whenTheVersionExists_returnsTheCredential() {
        val credentialVersionFound = this.subject
            .findVersionByUuid(VERSION_UUID_STRING)

        assertThat(credentialVersionFound).isEqualTo(existingCredentialVersion)
    }

    @Test
    fun findAllCertificateCredentialsByCaName_whenTheUserHasPermission_getsAllCertificateCredentialsByCaName() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(true)

        val expectedCertificates = newArrayList("expectedCertificate")
        `when`(credentialVersionDataService.findAllCertificateCredentialsByCaName(CREDENTIAL_NAME))
            .thenReturn(expectedCertificates)

        val foundCertificates = this.subject
            .findAllCertificateCredentialsByCaName(CREDENTIAL_NAME)

        assertThat(foundCertificates).isEqualTo(expectedCertificates)
    }

    @Test
    fun save_whenThereIsAnExistingCredentialAndParametersAreSame_DoesNotOverwriteCredential() {
        val generateRequest = mock(BaseCredentialGenerateRequest::class.java)
        `when`(generateRequest.name).thenReturn(CREDENTIAL_NAME)

        val stringGenerationParameters = StringGenerationParameters()
        `when`(generateRequest.generationParameters).thenReturn(stringGenerationParameters)

        val stringCredentialValue = StringCredentialValue("password")
        val passwordCredentialVersion = PasswordCredentialVersion(
            stringCredentialValue,
            stringGenerationParameters,
            encryptor
        )

        `when`(generateRequest.type).thenReturn("password")
        `when`(credentialVersionDataService.save(passwordCredentialVersion))
            .thenReturn(passwordCredentialVersion)
        val newVersion = PasswordCredentialVersion()

        val originalCredentialVersion = mock(CredentialVersion::class.java)
        `when`(originalCredentialVersion.matchesGenerationParameters(stringGenerationParameters)).thenReturn(true)

        `when`<CredentialVersion>(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(originalCredentialVersion)
        `when`(originalCredentialVersion.getCredentialType()).thenReturn("password")

        `when`(
            credentialFactory.makeNewCredentialVersion(
                CredentialType.valueOf("PASSWORD"),
                CREDENTIAL_NAME,
                credentialValue,
                originalCredentialVersion,
                generationParameters,
                null
            )
        ).thenReturn(newVersion)

        this.subject.save(originalCredentialVersion, credentialValue, generateRequest)

        verify(credentialVersionDataService, never()).save(newVersion)
    }

    @Test
    fun save_whenThereIsAnExistingCredentialAndNoOverwriteIsEnabled_DoesNotSave() {
        val generateRequest = mock(BaseCredentialGenerateRequest::class.java)
        `when`(generateRequest.isOverwrite).thenReturn(false)
        `when`(generateRequest.overwrite).thenReturn(false)
        `when`(generateRequest.name).thenReturn(CREDENTIAL_NAME)

        val stringGenerationParameters = StringGenerationParameters()
        `when`(generateRequest.generationParameters).thenReturn(stringGenerationParameters)

        `when`(generateRequest.type).thenReturn("password")

        val newVersion = PasswordCredentialVersion()

        val originalCredentialVersion = mock(CredentialVersion::class.java)
        `when`(originalCredentialVersion.matchesGenerationParameters(stringGenerationParameters)).thenReturn(false)

        `when`<CredentialVersion>(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(originalCredentialVersion)
        `when`(originalCredentialVersion.getCredentialType()).thenReturn("password")

        this.subject.save(originalCredentialVersion, credentialValue, generateRequest)

        verify(credentialFactory, never()).makeNewCredentialVersion(any(), any(), any(), any(), any(), any())
        verify(credentialVersionDataService, never()).save(newVersion)
    }

    @Test
    fun save_whenThereIsAnExistingCredentialAndParametersAreDifferent_OverwritesCredential() {
        val stringGenerationParameters = StringGenerationParameters()
        `when`(request.generationParameters).thenReturn(stringGenerationParameters)

        val stringCredentialValue = StringCredentialValue("password")
        val passwordCredentialVersion = PasswordCredentialVersion(
            stringCredentialValue,
            stringGenerationParameters,
            encryptor
        )

        `when`(request.type).thenReturn("password")
        `when`(credentialVersionDataService.save(passwordCredentialVersion))
            .thenReturn(passwordCredentialVersion)
        val newVersion = PasswordCredentialVersion()

        val originalCredentialVersion = mock(CredentialVersion::class.java)
        `when`(originalCredentialVersion.matchesGenerationParameters(stringGenerationParameters)).thenReturn(false)

        `when`<CredentialVersion>(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(originalCredentialVersion)
        `when`(originalCredentialVersion.getCredentialType()).thenReturn("password")

        `when`(
            credentialFactory.makeNewCredentialVersion(
                CredentialType.valueOf("PASSWORD"),
                CREDENTIAL_NAME,
                stringCredentialValue,
                originalCredentialVersion,
                stringGenerationParameters,
                null
            )
        ).thenReturn(newVersion)

        this.subject.save(originalCredentialVersion, stringCredentialValue, request)

        verify(credentialVersionDataService).save(newVersion)
    }

    @Test
    fun findByUuid_whenTheUUIDCorrespondsToACredential_andTheUserHasPermission_returnsTheCredential() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(true)

        assertThat(this.subject.findByUuid(CREDENTIAL_UUID)).isEqualTo(credential)
    }

    @Test
    fun findAllByName__whenConcatenateCasIsTrue__returnsSingleCa() {
        `when`<List<CredentialVersion>>(credentialVersionDataService.findAllByName("some-cert"))
            .thenReturn(listOf<CredentialVersion>(certificate))

        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = this.subject.findAllByName("some-cert")
        val resultCert = results[0] as CertificateCredentialVersion

        val allMatches = ArrayList<String>()
        val m = Pattern.compile("BEGIN CERTIFICATE")
            .matcher(resultCert.ca)
        while (m.find()) {
            allMatches.add(m.group())
        }
        assertThat(allMatches.size).isEqualTo(1)
    }

    @Test
    fun findNByName__whenConcatenateCasIsTrue__returnsSingleCa() {
        `when`<List<CredentialVersion>>(credentialVersionDataService.findNByName("some-cert", 1))
            .thenReturn(listOf<CredentialVersion>(certificate))

        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = this.subject.findNByName("some-cert", 1)
        val resultCert = results[0] as CertificateCredentialVersion

        val allMatches = ArrayList<String>()
        val m = Pattern.compile("BEGIN CERTIFICATE")
            .matcher(resultCert.ca)
        while (m.find()) {
            allMatches.add(m.group())
        }
        assertThat(allMatches.size).isEqualTo(1)
    }

    @Test
    fun findActiveByName__whenConcatenateCasIsTrue__returnsSingleCa() {
        `when`<List<CredentialVersion>>(credentialVersionDataService.findActiveByName("some-cert"))
            .thenReturn(listOf<CredentialVersion>(certificate))

        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = this.subject.findActiveByName("some-cert")
        val resultCert = results[0] as CertificateCredentialVersion

        val allMatches = ArrayList<String>()
        val m = Pattern.compile("BEGIN CERTIFICATE")
            .matcher(resultCert.ca)
        while (m.find()) {
            allMatches.add(m.group())
        }
        assertThat(allMatches.size).isEqualTo(1)
    }

    @Test
    fun findVersionByUuid__whenConcatenateCasIsTrue__returnsSingleCa() {
        `when`(credentialVersionDataService.findByUuid(certUuid.toString()))
            .thenReturn(certificate)

        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = this.subject.findVersionByUuid(certUuid.toString())
        val resultCert = results as CertificateCredentialVersion

        val allMatches = ArrayList<String>()
        val m = Pattern.compile("BEGIN CERTIFICATE")
            .matcher(resultCert.ca)
        while (m.find()) {
            allMatches.add(m.group())
        }
        assertThat(allMatches.size).isEqualTo(1)
    }

    @Test
    fun save_whenThereIsACertificateOverriddenDurationAndIsSet_ReturnsDurationOverridden() {
        val generateRequest = mock(BaseCredentialGenerateRequest::class.java)
        `when`(generateRequest.name).thenReturn(CREDENTIAL_NAME)
        `when`(generateRequest.type).thenReturn("certificate")
        `when`(generateRequest.overwrite).thenReturn(true)
        `when`(generateRequest.isOverwrite).thenReturn(true)

        val certificateCredentialValue = CertificateCredentialValue()

        val certificateCredentialVersion = CertificateCredentialVersion(CREDENTIAL_NAME)
        certificateCredentialVersion.durationOverridden = true

        val savedCertificateCredentialVersion = CertificateCredentialVersion(CREDENTIAL_NAME)
        savedCertificateCredentialVersion.durationOverridden = false

        val originalCredentialVersion = mock(CredentialVersion::class.java)
        `when`(originalCredentialVersion.matchesGenerationParameters(generateRequest.generationParameters)).thenReturn(false)
        `when`(
            credentialFactory.makeNewCredentialVersion(
                CredentialType.valueOf("CERTIFICATE"),
                CREDENTIAL_NAME,
                certificateCredentialValue,
                originalCredentialVersion,
                generateRequest.generationParameters,
                null
            )
        ).thenReturn(certificateCredentialVersion)
        `when`(originalCredentialVersion.getCredentialType()).thenReturn("certificate")

        `when`(credentialVersionDataService.save(certificateCredentialVersion))
            .thenReturn(savedCertificateCredentialVersion)

        val returnedCertificateCredentialVersion = this.subject.save(originalCredentialVersion, certificateCredentialValue, generateRequest) as CertificateCredentialVersion
        assertThat(returnedCertificateCredentialVersion.durationOverridden).isEqualTo(true)
    }

    companion object {
        private const val VERSION_UUID_STRING = "expected UUID"
        private val CREDENTIAL_UUID = UUID.randomUUID()
        private const val CREDENTIAL_NAME = "/TestCred"
        private const val USER = "Test-User"
    }
}

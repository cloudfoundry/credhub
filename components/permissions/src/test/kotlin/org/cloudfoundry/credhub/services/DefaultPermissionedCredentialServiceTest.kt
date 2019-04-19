package org.cloudfoundry.credhub.services

import com.google.common.collect.Lists.newArrayList
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.PermissionOperation.DELETE
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.entities.GetCredentialById
import org.cloudfoundry.credhub.auth.UserContext
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.data.CertificateAuthorityService
import org.cloudfoundry.credhub.data.CredentialDataService
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
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import org.mockito.MockitoAnnotations.initMocks
import java.util.ArrayList
import java.util.Arrays
import java.util.UUID
import java.util.regex.Pattern

class DefaultPermissionedCredentialServiceTest {

    @Mock
    private lateinit var credentialVersionDataService: CredentialVersionDataService

    @Mock
    private lateinit var permissionCheckingService: PermissionCheckingService

    @Mock
    private lateinit var encryptor: Encryptor

    @Mock
    private lateinit var credentialFactory: CredentialFactory

    @Mock
    private lateinit var certificateAuthorityService: CertificateAuthorityService

    @Mock
    private lateinit var credentialDataService: CredentialDataService

    @Mock
    private lateinit var auditRecord: CEFAuditRecord

    private lateinit var subjectWithoutConcatenateCas: DefaultPermissionedCredentialService
    private lateinit var subjectWithConcatenateCas: DefaultPermissionedCredentialService
    private lateinit var existingCredentialVersion: CredentialVersion
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

        subjectWithoutConcatenateCas = DefaultPermissionedCredentialService(
            credentialVersionDataService,
            credentialFactory,
            permissionCheckingService,
            certificateAuthorityService,
            userContextHolder,
            credentialDataService,
            auditRecord,
            false
        )

        subjectWithConcatenateCas = DefaultPermissionedCredentialService(
            credentialVersionDataService,
            credentialFactory,
            permissionCheckingService,
            certificateAuthorityService,
            userContextHolder,
            credentialDataService,
            auditRecord,
            true
        )

        generationParameters = mock<StringGenerationParameters>(StringGenerationParameters::class.java)
        credentialValue = mock<CredentialValue>(CredentialValue::class.java)
        credential = Credential(CREDENTIAL_NAME)
        accessControlEntries = ArrayList()

        `when`<String>(userContext.actor).thenReturn(USER)

        existingCredentialVersion = PasswordCredentialVersion(CREDENTIAL_NAME)
        existingCredentialVersion.setEncryptor(encryptor)

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
        certificate.credential.uuid = certUuid
        certificate.uuid = certUuid
        certificate.ca = TestConstants.TEST_CERTIFICATE
        `when`<List<CredentialVersion>>(credentialVersionDataService.findActiveByName(certificate.caName))
                .thenReturn(Arrays.asList<CredentialVersion>(nonTransitionalCa, transitionalCa))
    }

    @Test
    fun save_whenGivenTypeAndExistingTypeDontMatch_throwsException() {
        `when`(request.type).thenReturn("user")
        `when`<CredentialVersion>(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion)

        Assertions.assertThatThrownBy {
            subjectWithoutConcatenateCas.save(existingCredentialVersion, credentialValue, request)
        }.isInstanceOf(ParameterizedValidationException::class.java)
    }

    @Test
    fun delete_whenTheUserLacksPermission_throwsAnException() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, DELETE))
            .thenReturn(false)

        Assertions.assertThatThrownBy {
            subjectWithoutConcatenateCas.delete(CREDENTIAL_NAME)
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun findAllByName_whenTheUserLacksPermission_throwsAnException() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(false)

        Assertions.assertThatThrownBy {
            subjectWithoutConcatenateCas.findAllByName(CREDENTIAL_NAME)
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun findNByName_whenTheUserLacksPermission_throwsAnException() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(false)

        Assertions.assertThatThrownBy {
            subjectWithoutConcatenateCas.findNByName(CREDENTIAL_NAME, 1)
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun getNCredentialVersions_whenTheNumberOfCredentialsIsNegative_throws() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(true)

        Assertions.assertThatThrownBy {
            subjectWithoutConcatenateCas.findNByName(CREDENTIAL_NAME, -1)
        }.isInstanceOf(InvalidQueryParameterException::class.java)
            .hasMessage(ErrorMessages.INVALID_QUERY_PARAMETER)
    }

    @Test
    fun getCredentialVersion_whenTheVersionDoesNotExist_throwsException() {
        `when`<CredentialVersion>(credentialVersionDataService.findByUuid(VERSION_UUID_STRING))
            .thenReturn(null)

        Assertions.assertThatThrownBy {
            subjectWithoutConcatenateCas.findVersionByUuid(VERSION_UUID_STRING)
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun getCredentialVersion_whenTheUserLacksPermission_throwsExceptionAndSetsCorrectAuditingParameters() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(false)
        val passwordCredentialVersion = PasswordCredentialVersion(CREDENTIAL_NAME)
        val credential = Credential("hello")
        passwordCredentialVersion.credential = credential
        `when`<CredentialVersion>(credentialVersionDataService.findByUuid(VERSION_UUID_STRING))
            .thenReturn(passwordCredentialVersion)

        Assertions.assertThatThrownBy {
            subjectWithoutConcatenateCas.findVersionByUuid(VERSION_UUID_STRING)
            verify<CEFAuditRecord>(auditRecord, times(1)).addResource(credential)
            verify<CEFAuditRecord>(auditRecord, times(1)).addVersion(passwordCredentialVersion)
            verify<CEFAuditRecord>(auditRecord, times(1)).requestDetails = GetCredentialById(VERSION_UUID_STRING)
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun findAllCertificateCredentialsByCaName_whenTheUserLacksPermission_throwsException() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(false)

        Assertions.assertThatThrownBy {
            subjectWithoutConcatenateCas.findAllCertificateCredentialsByCaName(CREDENTIAL_NAME)
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun findByUuid_whenTheUUIDCorrespondsToACredential_andTheUserDoesNotHavePermission_throwsAnException() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(false)

        Assertions.assertThatThrownBy {
            subjectWithoutConcatenateCas.findByUuid(CREDENTIAL_UUID)
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun findByUuid_whenNoMatchingCredentialExists_throwsEntryNotFound() {
        Assertions.assertThatThrownBy {
            subjectWithoutConcatenateCas.findByUuid(UUID.randomUUID())
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun save_whenWritingCredential_savesANewVersion() {
        `when`(request.type).thenReturn("password")
        `when`<CredentialVersion>(credentialVersionDataService.findMostRecent(request.name)).thenReturn(null)
        val stringGenerationParameters = StringGenerationParameters()
        `when`<GenerationParameters>(request.generationParameters).thenReturn(stringGenerationParameters)

        val stringCredentialValue = StringCredentialValue("password")
        val passwordCredentialVersion = PasswordCredentialVersion(
            stringCredentialValue,
            request.generationParameters as StringGenerationParameters,
            encryptor)

        `when`<CredentialVersion>(credentialFactory.makeNewCredentialVersion(
            CredentialType.valueOf(request.type.toUpperCase()),
            request.name,
            stringCredentialValue,
            null,
            request.generationParameters)
        ).thenReturn(passwordCredentialVersion)

        subjectWithoutConcatenateCas.save(null, stringCredentialValue, request)

        verify(credentialVersionDataService).save(passwordCredentialVersion)
    }

    @Test
    fun findAllByName_addsToTheAuditRecord() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(true)

        val expectedCredentials = newArrayList<CredentialVersion>(existingCredentialVersion)
        `when`(credentialVersionDataService.findAllByName(CREDENTIAL_NAME))
            .thenReturn(expectedCredentials)

        subjectWithoutConcatenateCas.findAllByName(CREDENTIAL_NAME)

        verify(auditRecord, times(1)).addResource(ArgumentMatchers.any(Credential::class.java))
        verify(auditRecord, times(1)).addVersion(ArgumentMatchers.any(CredentialVersion::class.java))
    }

    @Test
    fun findActiveByName_addsToTheAuditRecord() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(true)

        val expectedCredentials = newArrayList(existingCredentialVersion)
        `when`<List<CredentialVersion>>(credentialVersionDataService.findActiveByName(CREDENTIAL_NAME))
            .thenReturn(expectedCredentials)

        subjectWithoutConcatenateCas.findActiveByName(CREDENTIAL_NAME)

        verify(auditRecord, times(1)).addResource(ArgumentMatchers.any(Credential::class.java))
        verify(auditRecord, times(1)).addVersion(ArgumentMatchers.any(CredentialVersion::class.java))
    }

    @Test
    fun findVersionByUuid_addsToTheAuditRecord() {
        `when`<CredentialVersion>(credentialVersionDataService.findByUuid(CREDENTIAL_UUID.toString()))
            .thenReturn(existingCredentialVersion)

        subjectWithoutConcatenateCas.findVersionByUuid(CREDENTIAL_UUID.toString())

        verify(auditRecord, times(1)).setResource(ArgumentMatchers.any(Credential::class.java))
        verify(auditRecord, times(1)).setVersion(ArgumentMatchers.any(CredentialVersion::class.java))
    }

    @Test
    fun getCredentialVersion_whenTheVersionExists_returnsTheCredential() {
        val credentialVersionFound = subjectWithoutConcatenateCas
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

        val foundCertificates = subjectWithoutConcatenateCas
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
            encryptor)

        `when`(generateRequest.type).thenReturn("password")
        `when`(credentialVersionDataService.save(passwordCredentialVersion))
            .thenReturn(passwordCredentialVersion)
        val newVersion = PasswordCredentialVersion()

        val originalCredentialVersion = mock(CredentialVersion::class.java)
        `when`(originalCredentialVersion.matchesGenerationParameters(stringGenerationParameters)).thenReturn(true)

        `when`<CredentialVersion>(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(originalCredentialVersion)
        `when`(originalCredentialVersion.credentialType).thenReturn("password")

        `when`(credentialFactory.makeNewCredentialVersion(
            CredentialType.valueOf("PASSWORD"),
            CREDENTIAL_NAME,
            credentialValue,
            originalCredentialVersion,
            generationParameters)).thenReturn(newVersion)

        subjectWithoutConcatenateCas.save(originalCredentialVersion, credentialValue, generateRequest)

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
            encryptor)

        `when`(request.type).thenReturn("password")
        `when`(credentialVersionDataService.save(passwordCredentialVersion))
            .thenReturn(passwordCredentialVersion)
        val newVersion = PasswordCredentialVersion()

        val originalCredentialVersion = mock(CredentialVersion::class.java)
        `when`(originalCredentialVersion.matchesGenerationParameters(stringGenerationParameters)).thenReturn(false)

        `when`<CredentialVersion>(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(originalCredentialVersion)
        `when`(originalCredentialVersion.credentialType).thenReturn("password")

        `when`(credentialFactory.makeNewCredentialVersion(
            CredentialType.valueOf("PASSWORD"),
            CREDENTIAL_NAME,
            stringCredentialValue,
            originalCredentialVersion,
            stringGenerationParameters)).thenReturn(newVersion)

        subjectWithoutConcatenateCas.save(originalCredentialVersion, stringCredentialValue, request)

        verify(credentialVersionDataService).save(newVersion)
    }

    @Test
    fun findByUuid_whenTheUUIDCorrespondsToACredential_andTheUserHasPermission_returnsTheCredential() {
        `when`(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
            .thenReturn(true)

        assertThat(subjectWithoutConcatenateCas.findByUuid(CREDENTIAL_UUID)).isEqualTo(credential)
    }

    @Test
    fun findAllByName__whenConcatenateCasIsTrue__returnsConcatenatedCas() {
        `when`<List<CredentialVersion>>(credentialVersionDataService.findAllByName("some-cert"))
                .thenReturn(listOf<CredentialVersion>(certificate))
        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = subjectWithConcatenateCas.findAllByName("some-cert")
        val resultCert = results[0] as CertificateCredentialVersion

        val allMatches = ArrayList<String>()
        val m = Pattern.compile("BEGIN CERTIFICATE")
                .matcher(resultCert.ca)
        while (m.find()) {
            allMatches.add(m.group())
        }
        assertThat(allMatches.size).isEqualTo(2)
    }

    @Test
    fun findAllByName__whenConcatenateCasIsFalse__returnsSingleCa() {
        `when`<List<CredentialVersion>>(credentialVersionDataService.findAllByName("some-cert"))
                .thenReturn(listOf<CredentialVersion>(certificate))

        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = subjectWithoutConcatenateCas.findAllByName("some-cert")
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
    fun findNByName__whenConcatenateCasIsTrue__returnsConcatenatedCas() {
        `when`<List<CredentialVersion>>(credentialVersionDataService.findNByName("some-cert", 1))
                .thenReturn(listOf<CredentialVersion>(certificate))
        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = subjectWithConcatenateCas.findNByName("some-cert", 1)
        val resultCert = results[0] as CertificateCredentialVersion

        val allMatches = ArrayList<String>()
        val m = Pattern.compile("BEGIN CERTIFICATE")
                .matcher(resultCert.ca)
        while (m.find()) {
            allMatches.add(m.group())
        }
        assertThat(allMatches.size).isEqualTo(2)
    }

    @Test
    fun findNByName__whenConcatenateCasIsFalse__returnsSingleCa() {
        `when`<List<CredentialVersion>>(credentialVersionDataService.findNByName("some-cert", 1))
                .thenReturn(listOf<CredentialVersion>(certificate))

        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = subjectWithoutConcatenateCas.findNByName("some-cert", 1)
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
    fun findActiveByName__whenConcatenateCasIsTrue__returnsConcatenatedCas() {
        `when`<List<CredentialVersion>>(credentialVersionDataService.findActiveByName("some-cert"))
                .thenReturn(listOf<CredentialVersion>(certificate))
        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = subjectWithConcatenateCas.findActiveByName("some-cert")
        val resultCert = results[0] as CertificateCredentialVersion

        val allMatches = ArrayList<String>()
        val m = Pattern.compile("BEGIN CERTIFICATE")
                .matcher(resultCert.ca)
        while (m.find()) {
            allMatches.add(m.group())
        }
        assertThat(allMatches.size).isEqualTo(2)
    }

    @Test
    fun findActiveByName__whenConcatenateCasIsFalse__returnsSingleCa() {
        `when`<List<CredentialVersion>>(credentialVersionDataService.findActiveByName("some-cert"))
                .thenReturn(listOf<CredentialVersion>(certificate))

        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = subjectWithoutConcatenateCas.findActiveByName("some-cert")
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
    fun findVersionByUuid__whenConcatenateCasIsTrue__returnsConcatenatedCas() {
        `when`(credentialVersionDataService.findByUuid(certUuid.toString()))
                .thenReturn(certificate)
        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = subjectWithConcatenateCas.findVersionByUuid(certUuid.toString())
        val resultCert = results as CertificateCredentialVersion

        val allMatches = ArrayList<String>()
        val m = Pattern.compile("BEGIN CERTIFICATE")
                .matcher(resultCert.ca)
        while (m.find()) {
            allMatches.add(m.group())
        }
        assertThat(allMatches.size).isEqualTo(2)
    }

    @Test
    fun findVersionByUuid__whenConcatenateCasIsFalse__returnsSingleCa() {
        `when`(credentialVersionDataService.findByUuid(certUuid.toString()))
                .thenReturn(certificate)

        `when`(permissionCheckingService.hasPermission(USER, "some-cert", PermissionOperation.READ)).thenReturn(true)

        val results = subjectWithoutConcatenateCas.findVersionByUuid(certUuid.toString())
        val resultCert = results as CertificateCredentialVersion

        val allMatches = ArrayList<String>()
        val m = Pattern.compile("BEGIN CERTIFICATE")
                .matcher(resultCert.ca)
        while (m.find()) {
            allMatches.add(m.group())
        }
        assertThat(allMatches.size).isEqualTo(1)
    }

    companion object {
        private const val VERSION_UUID_STRING = "expected UUID"
        private val CREDENTIAL_UUID = UUID.randomUUID()
        private const val CREDENTIAL_NAME = "/Picard"
        private const val USER = "Kirk"
    }
}

package org.cloudfoundry.credhub.handlers

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.PropertyNamingStrategy
import com.google.protobuf.ByteString
import io.grpc.Status
import io.grpc.StatusRuntimeException
import java.security.Security
import java.time.Instant
import java.util.UUID
import junit.framework.Assert.assertEquals
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.auth.UserContext
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.constants.CredentialWriteMode.NO_OVERWRITE
import org.cloudfoundry.credhub.constants.CredentialWriteMode.OVERWRITE
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.credential.JsonCredentialValue
import org.cloudfoundry.credhub.credential.RsaCredentialValue
import org.cloudfoundry.credhub.credential.SshCredentialValue
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.credential.UserCredentialValue
import org.cloudfoundry.credhub.credentials.RemoteCredentialsHandler
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters
import org.cloudfoundry.credhub.generate.UniversalCredentialGenerator
import org.cloudfoundry.credhub.remote.RemoteBackendClient
import org.cloudfoundry.credhub.remote.grpc.FindResponse
import org.cloudfoundry.credhub.remote.grpc.FindResult
import org.cloudfoundry.credhub.remote.grpc.GetResponse
import org.cloudfoundry.credhub.remote.grpc.SetResponse
import org.cloudfoundry.credhub.requests.CertificateGenerateRequest
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters
import org.cloudfoundry.credhub.requests.CertificateSetRequest
import org.cloudfoundry.credhub.requests.JsonSetRequest
import org.cloudfoundry.credhub.requests.PasswordGenerateRequest
import org.cloudfoundry.credhub.requests.PasswordSetRequest
import org.cloudfoundry.credhub.requests.RsaGenerateRequest
import org.cloudfoundry.credhub.requests.RsaGenerationParameters
import org.cloudfoundry.credhub.requests.RsaSetRequest
import org.cloudfoundry.credhub.requests.SshGenerateRequest
import org.cloudfoundry.credhub.requests.SshGenerationParameters
import org.cloudfoundry.credhub.requests.SshSetRequest
import org.cloudfoundry.credhub.requests.StringGenerationParameters
import org.cloudfoundry.credhub.requests.UserGenerateRequest
import org.cloudfoundry.credhub.requests.UserSetRequest
import org.cloudfoundry.credhub.requests.ValueSetRequest
import org.cloudfoundry.credhub.utils.TestConstants
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock

@RunWith(JUnit4::class)
class RemoteCredentialsHandlerTest {

    private val CREDENTIAL_NAME = "/test/credential"
    private val USER = "test-user"

    private val userContextHolder = mock<UserContextHolder>(UserContextHolder::class.java)!!
    private val objectMapper = ObjectMapper()
    private var client = mock<RemoteBackendClient>(RemoteBackendClient::class.java)!!
    private val credentialGenerator = mock<UniversalCredentialGenerator>(UniversalCredentialGenerator::class.java)!!
    private lateinit var subject: RemoteCredentialsHandler
    private lateinit var versionCreatedAt: String

    @Before
    fun beforeEach() {
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }

        objectMapper.propertyNamingStrategy = PropertyNamingStrategy.SNAKE_CASE

        subject = RemoteCredentialsHandler(
            userContextHolder,
            objectMapper,
            client,
            credentialGenerator)

        val userContext = mock(UserContext::class.java)
        `when`(userContext.actor).thenReturn(USER)
        `when`(userContextHolder.userContext).thenReturn(userContext)

        versionCreatedAt = Instant.now().toString()
    }

    @Test
    fun getCurrentCredentialVersion_withValueCredential_returnsCorrectDataReponse() {
        val type = "value"
        val uuid = "00000000-0000-0000-0000-000000000001"
        val stringCredential = StringCredentialValue("test-value")

        val byteValue = subject.createByteStringFromData(
            type,
            stringCredential
        )
        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(response)

        val result = subject.getCurrentCredentialVersions(CREDENTIAL_NAME)
        assertEquals(result.data.size, 1)
        assertEquals(result.data[0].type, type)
        assertEquals(result.data[0].uuid, uuid)
        assertThat(result.data[0].value).isInstanceOf(StringCredentialValue::class.java)
    }

    @Test
    fun getCurrentCredentialVersion_withJsonCredential_returnsCorrectDataResponse() {
        val type = "json"
        val uuid = "00000000-0000-0000-0000-000000000002"
        val jsonNode = objectMapper.readTree("""{"some-key": "some-value"} """.trimIndent())
        val jsonCredential = JsonCredentialValue(jsonNode)

        val byteValue = subject.createByteStringFromData(
            type,
            jsonCredential
        )

        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(response)

        val result = subject.getCurrentCredentialVersions(CREDENTIAL_NAME)
        assertEquals(result.data.size, 1)
        assertEquals(result.data[0].type, type)
        assertEquals(result.data[0].uuid, uuid)
        assertThat(result.data[0].value).isInstanceOf(JsonCredentialValue::class.java)
    }

    @Test
    fun getCurrentCredentialVersion_withCertificateCredential_returnsCorrectDataResponse() {
        val type = "certificate"
        val uuid = "00000000-0000-0000-0000-000000000003"
        val certificateCredential = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.TEST_PRIVATE_KEY,
            "/some-ca",
            false,
            false,
            false,
            false)

        val byteValue = subject.createByteStringFromData(
            type,
            certificateCredential
        )
        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(response)

        val result = subject.getCurrentCredentialVersions(CREDENTIAL_NAME)
        assertEquals(result.data.size, 1)
        assertEquals(result.data[0].type, type)
        assertEquals(result.data[0].uuid, uuid)
        assertThat(result.data[0].value).isInstanceOf(CertificateCredentialValue::class.java)
    }

    @Test
    fun getCurrentCredentialVersion_withPasswordCredential_returnsCorrectDataResponse() {
        val type = "password"
        val uuid = "00000000-0000-0000-0000-000000000004"
        val stringCredential = StringCredentialValue("test-password")

        val byteValue = subject.createByteStringFromData(
            type,
            stringCredential
        )
        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(response)

        val result = subject.getCurrentCredentialVersions(CREDENTIAL_NAME)
        assertEquals(result.data.size, 1)
        assertEquals(result.data[0].type, type)
        assertEquals(result.data[0].uuid, uuid)
        assertThat(result.data[0].value).isInstanceOf(StringCredentialValue::class.java)
    }

    @Test
    fun getCurrentCredentialVersion_withUserCredential_returnsCorrectDataResponse() {
        val type = "user"
        val uuid = "00000000-0000-0000-0000-000000000005"
        val username = "some-username"
        val password = "some-password"
        val salt = "salt"
        val userCredential = UserCredentialValue(username, password, salt)

        val byteValue = subject.createByteStringFromData(
            type,
            userCredential
        )

        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(response)

        val result = subject.getCurrentCredentialVersions(CREDENTIAL_NAME)
        assertEquals(result.data.size, 1)
        assertEquals(result.data[0].type, type)
        assertEquals(result.data[0].uuid, uuid)
        assertThat(result.data[0].value).isInstanceOf(UserCredentialValue::class.java)
    }

    @Test
    fun getCurrentCredentialVersion_withRsaCredential_returnsCorrectDataResponse() {
        val type = "rsa"
        val uuid = "00000000-0000-0000-0000-000000000006"
        val rsaCredential = RsaCredentialValue(TestConstants.RSA_PUBLIC_KEY_4096, TestConstants.PRIVATE_KEY_4096)

        val byteValue = subject.createByteStringFromData(
            type,
            rsaCredential
        )
        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(response)

        val result = subject.getCurrentCredentialVersions(CREDENTIAL_NAME)
        assertEquals(result.data.size, 1)
        assertEquals(result.data[0].type, type)
        assertEquals(result.data[0].uuid, uuid)
        assertThat(result.data[0].value).isInstanceOf(RsaCredentialValue::class.java)
    }

    @Test
    fun getCurrentCredentialVersion_withSshCredential_returnsCorrectDataResponse() {
        val type = "ssh"
        val uuid = "00000000-0000-0000-0000-000000000007"
        val sshCredential = SshCredentialValue(TestConstants.SSH_PUBLIC_KEY_4096, TestConstants.PRIVATE_KEY_4096, "fingerprint")

        val byteValue = subject.createByteStringFromData(
            type,
            sshCredential
        )
        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(response)

        val result = subject.getCurrentCredentialVersions(CREDENTIAL_NAME)
        assertEquals(result.data.size, 1)
        assertEquals(result.data[0].type, type)
        assertEquals(result.data[0].uuid, uuid)
        assertThat(result.data[0].value).isInstanceOf(SshCredentialValue::class.java)
    }

    @Test
    fun getCredentialVersionByUUID_withValueCredential_returnsCorrectDataReponse() {
        val type = "value"
        val uuid = "00000000-0000-0000-0000-000000000001"
        val stringCredential = StringCredentialValue("test-value")

        val byteValue = subject.createByteStringFromData(
            type,
            stringCredential
        )
        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByIdRequest(uuid, USER)).thenReturn(response)

        val result = subject.getCredentialVersionByUUID(uuid)
        assertEquals(result.type, type)
        assertEquals(result.uuid, uuid)
        assertThat(result.value).isInstanceOf(StringCredentialValue::class.java)
    }

    @Test
    fun getCredentialVersionByUUID_withJsonCredential_returnsCorrectDataResponse() {
        val type = "json"
        val uuid = "00000000-0000-0000-0000-000000000002"
        val jsonNode = objectMapper.readTree("""{"some-key": "some-value"} """.trimIndent())
        val jsonCredential = JsonCredentialValue(jsonNode)

        val byteValue = subject.createByteStringFromData(
            type,
            jsonCredential
        )

        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByIdRequest(uuid, USER)).thenReturn(response)

        val result = subject.getCredentialVersionByUUID(uuid)
        assertEquals(result.type, type)
        assertEquals(result.uuid, uuid)
        assertThat(result.value).isInstanceOf(JsonCredentialValue::class.java)
    }

    @Test
    fun getCredentialVersionByUUID_withCertificateCredential_returnsCorrectDataResponse() {
        val type = "certificate"
        val uuid = "00000000-0000-0000-0000-000000000003"
        val certificateCredential = CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                "/some-ca",
                false,
                false,
                false,
                false)

        val byteValue = subject.createByteStringFromData(
            type,
            certificateCredential
        )

        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByIdRequest(uuid, USER)).thenReturn(response)

        val result = subject.getCredentialVersionByUUID(uuid)
        assertEquals(result.type, type)
        assertEquals(result.uuid, uuid)
        assertThat(result.value).isInstanceOf(CertificateCredentialValue::class.java)
    }

    @Test
    fun getCredentialVersionByUUID_withPasswordCredential_returnsCorrectDataResponse() {
        val type = "password"
        val uuid = "00000000-0000-0000-0000-000000000004"
        val stringCredential = StringCredentialValue("test-password")

        val byteValue = subject.createByteStringFromData(
            type,
            stringCredential
        )

        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByIdRequest(uuid, USER)).thenReturn(response)

        val result = subject.getCredentialVersionByUUID(uuid)
        assertEquals(result.type, type)
        assertEquals(result.uuid, uuid)
        assertThat(result.value).isInstanceOf(StringCredentialValue::class.java)
    }

    @Test
    fun getCredentialVersionByUUID_withUserCredential_returnsCorrectDataResponse() {
        val type = "user"
        val uuid = "00000000-0000-0000-0000-000000000005"
        val username = "some-username"
        val password = "some-password"
        val salt = "salt"
        val userCredential = UserCredentialValue(username, password, salt)

        val byteValue = subject.createByteStringFromData(
            type,
            userCredential
        )
        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByIdRequest(uuid, USER)).thenReturn(response)

        val result = subject.getCredentialVersionByUUID(uuid)
        assertEquals(result.type, type)
        assertEquals(result.uuid, uuid)
        assertThat(result.value).isInstanceOf(UserCredentialValue::class.java)
    }

    @Test
    fun getCredentialVersionByUUID_withRsaCredential_returnsCorrectDataResponse() {
        val type = "rsa"
        val uuid = "00000000-0000-0000-0000-000000000006"
        val rsaCredential = RsaCredentialValue(TestConstants.RSA_PUBLIC_KEY_4096, TestConstants.PRIVATE_KEY_4096)

        val byteValue = subject.createByteStringFromData(
            type,
            rsaCredential
        )

        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByIdRequest(uuid, USER)).thenReturn(response)

        val result = subject.getCredentialVersionByUUID(uuid)
        assertEquals(result.type, type)
        assertEquals(result.uuid, uuid)
        assertThat(result.value).isInstanceOf(RsaCredentialValue::class.java)
    }

    @Test
    fun getCredentialVersionByUUID_withSshCredential_returnsCorrectDataResponse() {
        val type = "ssh"
        val uuid = "00000000-0000-0000-0000-000000000006"
        val sshCredential = SshCredentialValue(TestConstants.SSH_PUBLIC_KEY_4096, TestConstants.PRIVATE_KEY_4096, "fingerprint")

        val byteValue = subject.createByteStringFromData(
            type,
            sshCredential
        )

        val response = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(byteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt).build()
        `when`(client.getByIdRequest(uuid, USER)).thenReturn(response)

        val result = subject.getCredentialVersionByUUID(uuid)
        assertEquals(result.type, type)
        assertEquals(result.uuid, uuid)
        assertThat(result.value).isInstanceOf(SshCredentialValue::class.java)
    }

    @Test
    fun setCredential_withValueCredential_returnsCorrectDataResponse() {
        val type = "value"
        val uuid = UUID.randomUUID().toString()
        val stringCredential = StringCredentialValue("test-value")

        val byteValue = subject.createByteStringFromData(
            type,
            stringCredential
        )

        val response = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(byteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, byteValue, USER, ByteString.EMPTY)).thenReturn(response)

        val request = ValueSetRequest()
        request.value = stringCredential
        request.name = CREDENTIAL_NAME
        request.type = type

        val result = subject.setCredential(request)
        assertEquals(type, result.type)
        assertEquals(uuid, result.uuid)
        assertEquals(stringCredential, request.value)
        assertEquals(CREDENTIAL_NAME, result.name)
        assertThat(result.value).isInstanceOf(StringCredentialValue::class.java)
    }

    @Test
    fun setCredential_withPasswordCredential_returnsCorrectDataResponse() {
        val type = "password"
        val uuid = UUID.randomUUID().toString()
        val stringCredential = StringCredentialValue("test-password")

        val byteValue = subject.createByteStringFromData(
            type,
            stringCredential
        )

        val response = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(byteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, byteValue, USER, ByteString.EMPTY)).thenReturn(response)

        val request = PasswordSetRequest()
        request.password = stringCredential
        request.name = CREDENTIAL_NAME
        request.type = type

        val result = subject.setCredential(request)
        assertEquals(type, result.type)
        assertEquals(uuid, result.uuid)
        assertEquals(stringCredential, request.password)
        assertEquals(CREDENTIAL_NAME, result.name)
        assertThat(result.value).isInstanceOf(StringCredentialValue::class.java)
    }

    @Test
    fun setCredential_withJsonCredential_returnsCorrectDataResponse() {
        val type = "json"
        val jsonNode = objectMapper.readTree("""{"some-key": "some-value"} """)
        val uuid = UUID.randomUUID().toString()
        val jsonCredential = JsonCredentialValue(jsonNode)

        val byteValue = subject.createByteStringFromData(
            type,
            jsonCredential
        )

        val response = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(byteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, byteValue, USER, ByteString.EMPTY)).thenReturn(response)

        val request = JsonSetRequest()
        request.value = jsonCredential
        request.name = CREDENTIAL_NAME
        request.type = type

        val result = subject.setCredential(request)
        assertEquals(type, result.type)
        assertEquals(uuid, result.uuid)
        assertEquals(jsonCredential, request.value)
        assertEquals(CREDENTIAL_NAME, result.name)
        assertThat(result.value).isInstanceOf(JsonCredentialValue::class.java)
    }

    @Test
    fun setCredential_withCertificateCredential_returnsCorrectDataResponse() {
        val type = "certificate"
        val uuid = UUID.randomUUID().toString()
        val certificateCredential = CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                "/some-ca",
                false,
                false,
                false,
                false)

        val byteValue = subject.createByteStringFromData(
            type,
            certificateCredential
        )

        val response = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(byteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, byteValue, USER, ByteString.EMPTY)).thenReturn(response)

        val request = CertificateSetRequest()
        request.certificateValue = certificateCredential
        request.name = CREDENTIAL_NAME
        request.type = type

        val result = subject.setCredential(request)
        assertEquals(type, result.type)
        assertEquals(uuid, result.uuid)
        assertEquals(certificateCredential, request.certificateValue)
        assertEquals(CREDENTIAL_NAME, result.name)
        assertThat(result.value).isInstanceOf(CertificateCredentialValue::class.java)
    }

    @Test
    fun setCredential_withUserCredential_returnsCorrectDataResponse() {
        val type = "user"
        val uuid = UUID.randomUUID().toString()
        val username = "some-username"
        val password = "some-password"
        val salt = "salt"
        val userCredential = UserCredentialValue(username, password, salt)

        val byteValue = subject.createByteStringFromData(
            type,
            userCredential
        )

        val response = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(byteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, byteValue, USER, ByteString.EMPTY)).thenReturn(response)

        val request = UserSetRequest()
        request.userValue = userCredential
        request.name = CREDENTIAL_NAME
        request.type = type

        val result = subject.setCredential(request)
        assertEquals(type, result.type)
        assertEquals(uuid, result.uuid)
        assertEquals(userCredential, request.userValue)
        assertEquals(CREDENTIAL_NAME, result.name)
        assertThat(result.value).isInstanceOf(UserCredentialValue::class.java)
    }

    @Test
    fun setCredential_withRsaCredential_returnsCorrectDataResponse() {
        val type = "rsa"
        val uuid = UUID.randomUUID().toString()
        val rsaCredential = RsaCredentialValue(TestConstants.RSA_PUBLIC_KEY_4096, TestConstants.PRIVATE_KEY_4096)

        val byteValue = subject.createByteStringFromData(
            type,
            rsaCredential
        )

        val response = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(byteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, byteValue, USER, ByteString.EMPTY)).thenReturn(response)

        val request = RsaSetRequest()
        request.rsaKeyValue = rsaCredential
        request.name = CREDENTIAL_NAME
        request.type = type

        val result = subject.setCredential(request)
        assertEquals(type, result.type)
        assertEquals(uuid, result.uuid)
        assertEquals(rsaCredential, request.rsaKeyValue)
        assertEquals(CREDENTIAL_NAME, result.name)
        assertThat(result.value).isInstanceOf(RsaCredentialValue::class.java)
    }

    @Test
    fun setCredential_withSshCredential_returnsCorrectDataResponse() {
        val type = "ssh"
        val uuid = UUID.randomUUID().toString()
        val sshCredential = SshCredentialValue(TestConstants.SSH_PUBLIC_KEY_4096, TestConstants.PRIVATE_KEY_4096, "fingerprint")

        val byteValue = subject.createByteStringFromData(
            type,
            sshCredential
        )

        val response = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(byteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, byteValue, USER, ByteString.EMPTY)).thenReturn(response)

        val request = SshSetRequest()
        request.sshKeyValue = sshCredential
        request.name = CREDENTIAL_NAME
        request.type = type

        val result = subject.setCredential(request)
        assertEquals(type, result.type)
        assertEquals(uuid, result.uuid)
        assertEquals(sshCredential, request.sshKeyValue)
        assertEquals(CREDENTIAL_NAME, result.name)
        assertThat(result.value).isInstanceOf(SshCredentialValue::class.java)
    }

    @Test
    fun deleteCredential_whenCredentialExists_doesNotThrowException() {
        subject.deleteCredential(CREDENTIAL_NAME)
    }

    @Test
    fun findCredential_withName_returnsCorrectDataResponse() {
        val response = FindResponse
            .newBuilder()
            .addResults(FindResult
                .newBuilder()
                .setName("/test/some-other-credential")
                .setVersionCreatedAt(versionCreatedAt))
            .addResults(FindResult
                .newBuilder()
                .setName("/test/another-credential")
                .setVersionCreatedAt(versionCreatedAt))
            .build()

        `when`(client.findContainingNameRequest("other", USER)).thenReturn(response)

        val result = subject.findContainingName("other", "365")

        assertEquals(result.size, 2)
        assertEquals(result.get(0).name, "/test/some-other-credential")
        assertEquals(result.get(1).name, "/test/another-credential")
        assertEquals(result.get(0).versionCreatedAt.toString(), versionCreatedAt)
        assertEquals(result.get(1).versionCreatedAt.toString(), versionCreatedAt)
    }

    @Test
    fun findStarting_withPath_returnsCorrectDataResponse() {
        val response = FindResponse
            .newBuilder()
            .addResults(FindResult
                .newBuilder()
                .setName("/test/some-other-credential")
                .setVersionCreatedAt(versionCreatedAt))
            .addResults(FindResult
                .newBuilder()
                .setName("/test/another-credential")
                .setVersionCreatedAt(versionCreatedAt))
            .build()

        `when`(client.findStartingWithPathRequest("/test", USER)).thenReturn(response)

        val result = subject.findStartingWithPath("/test", "365")

        assertEquals(result.size, 2)
        assertEquals(result.get(0).name, "/test/some-other-credential")
        assertEquals(result.get(1).name, "/test/another-credential")
        assertEquals(result.get(0).versionCreatedAt.toString(), versionCreatedAt)
        assertEquals(result.get(1).versionCreatedAt.toString(), versionCreatedAt)
    }

    @Test
    fun generatePassword_whenExistingPasswordMatchesGenerationParameters_doesNotRegenerate() {
        val type = "password"
        val uuid = UUID.randomUUID().toString()
        val shouldntBeReturned = StringCredentialValue("1bad-password")
        val shouldBeReturned = StringCredentialValue("good-password")

        val generationParameters = StringGenerationParameters()
        generationParameters.length = 13
        generationParameters.isExcludeLower = false
        generationParameters.isExcludeNumber = false
        generationParameters.isExcludeUpper = false
        generationParameters.isIncludeSpecial = false

        val oldByteValue = subject.createByteStringFromData(type, shouldBeReturned)
        val getResponse = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(oldByteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt)
            .setGenerationParameters(subject.createByteStringFromGenerationParameters(type, generationParameters))
            .build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(getResponse)

        val newByteValue = subject.createByteStringFromData(type, shouldntBeReturned)
        val byteGenerationParameters = subject.createByteStringFromGenerationParameters(type, generationParameters)
        val setResponse = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(newByteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, newByteValue, USER, byteGenerationParameters)).thenReturn(setResponse)

        val passwordGenerateRequest = PasswordGenerateRequest()
        passwordGenerateRequest.setGenerationParameters(generationParameters)
        passwordGenerateRequest.name = CREDENTIAL_NAME
        passwordGenerateRequest.type = type

        `when`(credentialGenerator.generate(passwordGenerateRequest)).thenReturn(shouldntBeReturned)

        val generateResponse = subject.generateCredential(passwordGenerateRequest)
        val actualValue = (generateResponse.value as StringCredentialValue).stringCredential.toString()

        assertThat(actualValue).isEqualTo(shouldBeReturned.stringCredential.toString())
    }

    @Test
    fun generateCertificate_whenExistingCertificateMatchesGenerationParameters_doesNotRegenerate() {
        val type = "certificate"
        val uuid = UUID.randomUUID().toString()

        val shouldntBeReturned = CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                "/some-ca",
                false,
                false,
                true,
                false)

        val shouldBeReturned = CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.OTHER_TEST_CERTIFICATE,
                TestConstants.OTHER_TEST_PRIVATE_KEY,
                "/some-ca",
                false,
                false,
                true,
                false)

        val generationRequestParameters = CertificateGenerationRequestParameters()
        generationRequestParameters.caName = "some-ca"
        generationRequestParameters.commonName = "some-common-name"

        val generationParameters = CertificateGenerationParameters(generationRequestParameters)

        val oldByteValue = subject.createByteStringFromData(type, shouldBeReturned)
        val getResponse = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(oldByteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt)
            .setGenerationParameters(subject.createByteStringFromGenerationParameters(type, generationParameters))
            .build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(getResponse)

        val newByteValue = subject.createByteStringFromData(type, shouldntBeReturned)
        val byteGenerationParameters = subject.createByteStringFromGenerationParameters(type, generationParameters)
        val setResponse = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(newByteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, newByteValue, USER, byteGenerationParameters)).thenReturn(setResponse)

        val certificateGenerateRequest = CertificateGenerateRequest()
        certificateGenerateRequest.setRequestGenerationParameters(generationRequestParameters)
        certificateGenerateRequest.setCertificateGenerationParameters(generationParameters)
        certificateGenerateRequest.name = CREDENTIAL_NAME
        certificateGenerateRequest.type = type

        `when`(credentialGenerator.generate(certificateGenerateRequest)).thenReturn(shouldntBeReturned)

        val generateResponse = subject.generateCredential(certificateGenerateRequest)
        val actualValue = (generateResponse.value as CertificateCredentialValue).certificate

        assertThat(actualValue).isEqualTo(shouldBeReturned.certificate)
    }

    @Test
    fun generateSsh_whenExistingSshMatchesGenerationParameters_doesNotRegenerate() {
        val type = "ssh"
        val uuid = UUID.randomUUID().toString()
        val shouldntBeReturned = SshCredentialValue(TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT, TestConstants.PRIVATE_KEY_4096, "fingerprint")
        val shouldBeReturned = SshCredentialValue(TestConstants.SSH_PUBLIC_KEY_4096, TestConstants.PRIVATE_KEY_4096, "fingerprint")

        val generationParameters = SshGenerationParameters()
        generationParameters.keyLength = 4096

        val oldByteValue = subject.createByteStringFromData(type, shouldBeReturned)
        val getResponse = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(oldByteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt)
            .setGenerationParameters(subject.createByteStringFromGenerationParameters(type, generationParameters))
            .build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(getResponse)

        val newByteValue = subject.createByteStringFromData(type, shouldntBeReturned)
        val byteGenerationParameters = subject.createByteStringFromGenerationParameters(type, generationParameters)
        val setResponse = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(newByteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, newByteValue, USER, byteGenerationParameters)).thenReturn(setResponse)

        val sshGenerateRequest = SshGenerateRequest()
        sshGenerateRequest.setGenerationParameters(generationParameters)
        sshGenerateRequest.name = CREDENTIAL_NAME
        sshGenerateRequest.type = type

        `when`(credentialGenerator.generate(sshGenerateRequest)).thenReturn(shouldntBeReturned)

        val generateResponse = subject.generateCredential(sshGenerateRequest)
        val actualValue = (generateResponse.value as SshCredentialValue).publicKey

        assertThat(actualValue).isEqualTo(shouldBeReturned.publicKey)
    }

    @Test
    fun generateRsa_whenExistingRsaMatchesGenerationParameters_doesNotRegenerate() {
        val type = "rsa"
        val uuid = UUID.randomUUID().toString()
        val shouldntBeReturned = RsaCredentialValue(TestConstants.RSA_PUBLIC_KEY_4096 + "fake data", TestConstants.PRIVATE_KEY_4096)

        val shouldBeReturned = RsaCredentialValue(TestConstants.RSA_PUBLIC_KEY_4096, TestConstants.PRIVATE_KEY_4096)

        val generationParameters = RsaGenerationParameters()
        generationParameters.keyLength = 4096

        val oldByteValue = subject.createByteStringFromData(type, shouldBeReturned)
        val getResponse = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(oldByteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt)
            .setGenerationParameters(subject.createByteStringFromGenerationParameters(type, generationParameters))
            .build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(getResponse)

        val newByteValue = subject.createByteStringFromData(type, shouldntBeReturned)
        val byteGenerationParameters = subject.createByteStringFromGenerationParameters(type, generationParameters)
        val setResponse = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(newByteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, newByteValue, USER, byteGenerationParameters)).thenReturn(setResponse)

        val rsaGenerateRequest = RsaGenerateRequest()
        rsaGenerateRequest.setGenerationParameters(generationParameters)
        rsaGenerateRequest.name = CREDENTIAL_NAME
        rsaGenerateRequest.type = type

        `when`(credentialGenerator.generate(rsaGenerateRequest)).thenReturn(shouldntBeReturned)

        val generateResponse = subject.generateCredential(rsaGenerateRequest)
        val actualValue = (generateResponse.value as RsaCredentialValue).publicKey

        assertThat(actualValue).isEqualTo(shouldBeReturned.publicKey)
    }

    @Test
    fun generateUser_whenExistingUserMatchesGenerationParameters_doesNotRegenerate() {
        val type = "user"
        val uuid = UUID.randomUUID().toString()
        val shouldntBeReturned = UserCredentialValue("user2", "passwardo", "yesplease")
        val shouldBeReturned = UserCredentialValue("user1", "passvard", "nothanksidontlikesalt")

        val generationParameters = StringGenerationParameters()
        generationParameters.length = 4
        generationParameters.isExcludeLower = false
        generationParameters.isExcludeNumber = false
        generationParameters.isExcludeUpper = false
        generationParameters.isIncludeSpecial = false

        val oldByteValue = subject.createByteStringFromData(type, shouldBeReturned)
        val getResponse = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(oldByteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt)
            .setGenerationParameters(subject.createByteStringFromGenerationParameters(type, generationParameters))
            .build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(getResponse)

        val newByteValue = subject.createByteStringFromData(type, shouldntBeReturned)
        val byteGenerationParameters = subject.createByteStringFromGenerationParameters(type, generationParameters)
        val setResponse = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(newByteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, newByteValue, USER, byteGenerationParameters)).thenReturn(setResponse)

        val userGenerateRequest = UserGenerateRequest()
        userGenerateRequest.setGenerationParameters(generationParameters)
        userGenerateRequest.name = CREDENTIAL_NAME
        userGenerateRequest.type = type

        `when`(credentialGenerator.generate(userGenerateRequest)).thenReturn(shouldntBeReturned)

        val generateResponse = subject.generateCredential(userGenerateRequest)
        val actualValue = (generateResponse.value as UserCredentialValue).username

        assertThat(actualValue).isEqualTo(shouldBeReturned.username)
    }

    @Test
    fun generatePassword_whenExistingPasswordGenerationParametersDontMatch_generateNewCredential() {
        val type = "password"
        val uuid = UUID.randomUUID().toString()
        val password = StringCredentialValue("good-password")
        val newPassword = StringCredentialValue("H38FHHFUFUFYTYTYTYTYTYTYTYTYTYTYT")

        val generationParameters = StringGenerationParameters()
        generationParameters.length = 13
        generationParameters.isExcludeLower = false
        generationParameters.isExcludeNumber = false
        generationParameters.isExcludeUpper = false
        generationParameters.isIncludeSpecial = false

        val newGenerationParameters = StringGenerationParameters()
        generationParameters.length = 32
        generationParameters.isExcludeLower = true
        generationParameters.isExcludeNumber = false
        generationParameters.isExcludeUpper = false
        generationParameters.isIncludeSpecial = false

        val oldByteValue = subject.createByteStringFromData(type, password)
        val getResponse = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(oldByteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt)
            .setGenerationParameters(subject.createByteStringFromGenerationParameters(type, generationParameters))
            .build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(getResponse)

        val newByteValue = subject.createByteStringFromData(type, newPassword)
        val byteGenerationParameters = subject.createByteStringFromGenerationParameters(type, newGenerationParameters)
        val setResponse = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(newByteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, newByteValue, USER, byteGenerationParameters)).thenReturn(setResponse)

        val passwordGenerateRequest = PasswordGenerateRequest()
        passwordGenerateRequest.setGenerationParameters(newGenerationParameters)
        passwordGenerateRequest.name = CREDENTIAL_NAME
        passwordGenerateRequest.type = type

        `when`(credentialGenerator.generate(passwordGenerateRequest)).thenReturn(newPassword)

        val generateResponse = subject.generateCredential(passwordGenerateRequest)
        val actualValue = (generateResponse.value as StringCredentialValue).stringCredential.toString()

        assertThat(actualValue).isNotEqualTo(password.stringCredential.toString())
    }

    @Test
    fun generatePassword_whenOverwriteParameterIsSet_andGenerationParametersAreEqual_stillGenerateNewCredential() {
        val type = "password"
        val uuid = UUID.randomUUID().toString()
        val newPassword = StringCredentialValue("nice-password")
        val originalPassword = StringCredentialValue("good-password")

        val generationParameters = StringGenerationParameters()
        generationParameters.length = 13
        generationParameters.isExcludeLower = false
        generationParameters.isExcludeNumber = false
        generationParameters.isExcludeUpper = false
        generationParameters.isIncludeSpecial = false

        val oldByteValue = subject.createByteStringFromData(type, originalPassword)
        val getResponse = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(oldByteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt)
            .setGenerationParameters(subject.createByteStringFromGenerationParameters(type, generationParameters))
            .build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(getResponse)

        val newByteValue = subject.createByteStringFromData(type, newPassword)
        val byteGenerationParameters = subject.createByteStringFromGenerationParameters(type, generationParameters)
        val setResponse = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(newByteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, newByteValue, USER, byteGenerationParameters)).thenReturn(setResponse)

        val passwordGenerateRequest = PasswordGenerateRequest()
        passwordGenerateRequest.setGenerationParameters(generationParameters)
        passwordGenerateRequest.name = CREDENTIAL_NAME
        passwordGenerateRequest.type = type
        passwordGenerateRequest.mode = OVERWRITE

        `when`(credentialGenerator.generate(passwordGenerateRequest)).thenReturn(newPassword)

        val generateResponse = subject.generateCredential(passwordGenerateRequest)
        val actualValue = (generateResponse.value as StringCredentialValue).stringCredential.toString()

        assertThat(actualValue).isEqualTo(newPassword.stringCredential.toString())
    }

    @Test
    fun generatePassword_whenNoOverwriteParameterIsSet_andGenerationParametersAreNotEqual_doNotGenerateNewCredential() {
        val type = "password"
        val uuid = UUID.randomUUID().toString()
        val newPassword = StringCredentialValue("nice-password")
        val originalPassword = StringCredentialValue("good-password")

        val generationParameters = StringGenerationParameters()
        generationParameters.length = 13
        generationParameters.isExcludeLower = false
        generationParameters.isExcludeNumber = false
        generationParameters.isExcludeUpper = false
        generationParameters.isIncludeSpecial = false

        val oldByteValue = subject.createByteStringFromData(type, originalPassword)
        val getResponse = GetResponse.newBuilder().setName(CREDENTIAL_NAME)
            .setType(type).setData(oldByteValue)
            .setId(uuid).setVersionCreatedAt(versionCreatedAt)
            .setGenerationParameters(subject.createByteStringFromGenerationParameters(type, generationParameters))
            .build()
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenReturn(getResponse)

        val newGenerationParameters = StringGenerationParameters()
        newGenerationParameters.length = 13
        newGenerationParameters.isExcludeLower = false
        newGenerationParameters.isExcludeNumber = true
        newGenerationParameters.isExcludeUpper = false
        newGenerationParameters.isIncludeSpecial = false

        val newByteValue = subject.createByteStringFromData(type, newPassword)
        val byteGenerationParameters = subject.createByteStringFromGenerationParameters(type, newGenerationParameters)
        val setResponse = SetResponse.newBuilder()
            .setName(CREDENTIAL_NAME)
            .setVersionCreatedAt(versionCreatedAt)
            .setType(type)
            .setData(newByteValue)
            .setId(uuid)
            .build()
        `when`(client.setRequest(CREDENTIAL_NAME, type, newByteValue, USER, byteGenerationParameters)).thenReturn(setResponse)

        val passwordGenerateRequest = PasswordGenerateRequest()
        passwordGenerateRequest.setGenerationParameters(newGenerationParameters)
        passwordGenerateRequest.name = CREDENTIAL_NAME
        passwordGenerateRequest.type = type
        passwordGenerateRequest.mode = NO_OVERWRITE

        `when`(credentialGenerator.generate(passwordGenerateRequest)).thenReturn(newPassword)

        val generateResponse = subject.generateCredential(passwordGenerateRequest)
        val actualValue = (generateResponse.value as StringCredentialValue).stringCredential.toString()

        assertThat(actualValue).isEqualTo(originalPassword.stringCredential.toString())
    }

    @Test
    fun getCredentialByName_whenCredentialDoesNotExist_throwsCorrectError() {
        val exception = StatusRuntimeException(Status.NOT_FOUND)
        `when`(client.getByNameRequest(CREDENTIAL_NAME, USER)).thenThrow(exception)

        Assertions.assertThatThrownBy {
            subject.getCurrentCredentialVersions(CREDENTIAL_NAME)
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun getCredentialById_whenCredentialDoesNotExist_throwsCorrectError() {
        val uuid = UUID.randomUUID().toString()
        val exception = StatusRuntimeException(Status.NOT_FOUND)
        `when`(client.getByIdRequest(uuid, USER)).thenThrow(exception)

        Assertions.assertThatThrownBy {
            subject.getCredentialVersionByUUID(uuid)
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun setCredential_whenUserDoesNotHavePermission_throwsCorrectError() {
        val type = "value"
        val stringCredential = StringCredentialValue("test-value")
        val byteValue = subject.createByteStringFromData(
            type,
            stringCredential
        )
        val exception = StatusRuntimeException(Status.NOT_FOUND)
        `when`(client.setRequest(CREDENTIAL_NAME, type, byteValue, USER, ByteString.EMPTY)).thenThrow(exception)

        val request = ValueSetRequest()
        request.value = stringCredential
        request.name = CREDENTIAL_NAME
        request.type = type

        Assertions.assertThatThrownBy {
            subject.setCredential(request)
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun findContainingName_whenUserDoesNotHavePermission_throwsCorrectError() {
        val exception = StatusRuntimeException(Status.NOT_FOUND)
        `when`(client.findContainingNameRequest(CREDENTIAL_NAME, USER)).thenThrow(exception)

        Assertions.assertThatThrownBy {
            subject.findContainingName(CREDENTIAL_NAME, "365")
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun findStartingWithPath_whenUserDoesNotHavePermission_throwsCorrectError() {
        val exception = StatusRuntimeException(Status.NOT_FOUND)
        `when`(client.findStartingWithPathRequest("/", USER)).thenThrow(exception)

        Assertions.assertThatThrownBy {
            subject.findStartingWithPath("/", "365")
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    @Test
    fun deleteCredential_whenUserDoesNotHavePermission_throwsCorrectError() {
        val exception = StatusRuntimeException(Status.NOT_FOUND)
        `when`(client.deleteRequest(CREDENTIAL_NAME, USER)).thenThrow(exception)

        Assertions.assertThatThrownBy {
            subject.deleteCredential(CREDENTIAL_NAME)
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }
}

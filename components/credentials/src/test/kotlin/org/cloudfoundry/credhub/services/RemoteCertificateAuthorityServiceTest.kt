package org.cloudfoundry.credhub.services

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.PropertyNamingStrategy
import com.google.protobuf.ByteString
import io.grpc.Status
import io.grpc.StatusRuntimeException
import org.assertj.core.api.Assertions
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.auth.UserContext
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters
import org.cloudfoundry.credhub.remote.RemoteBackendClient
import org.cloudfoundry.credhub.remote.grpc.GetResponse
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters
import org.cloudfoundry.credhub.utils.TestConstants
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.util.UUID

@RunWith(JUnit4::class)
class RemoteCertificateAuthorityServiceTest {

    private val CA_NAME = "/test/ca"
    private val USER = "test-user"

    private lateinit var subject: RemoteCertificateAuthorityService
    private val userContextHolder = mock(UserContextHolder::class.java)!!
    private val objectMapper = ObjectMapper()
    private var client = mock(RemoteBackendClient::class.java)!!

    @Before
    fun beforeEach() {
        objectMapper.propertyNamingStrategy = PropertyNamingStrategy.SNAKE_CASE

        subject = RemoteCertificateAuthorityService(userContextHolder, objectMapper, client)

        val userContext = mock(UserContext::class.java)
        `when`(userContext.actor).thenReturn(USER)
        `when`(userContextHolder.userContext).thenReturn(userContext)
    }

    @Test
    fun findActiveVersion_whenCaExists_returnsCorrectCredentialValue() {
        val id = UUID.randomUUID()
        val shouldBeReturned = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.OTHER_TEST_CERTIFICATE,
            TestConstants.OTHER_TEST_PRIVATE_KEY,
            "/some-ca",
            true,
            true,
            true,
            false)

        val requestParams = CertificateGenerationRequestParameters()
        requestParams.caName = "some-ca"
        requestParams.commonName = "some-common-name"
        val generationParameters = CertificateGenerationParameters(requestParams)

        val response = GetResponse.newBuilder()
            .setName(CA_NAME)
            .setId(id.toString())
            .setType("certificate")
            .setGenerationParameters(createByteStringFromGenerationParameters(generationParameters))
            .setData(createByteStringFromData(shouldBeReturned))
            .build()

        `when`(client.getByNameRequest(CA_NAME, USER)).thenReturn(response)

        val result = subject.findActiveVersion(CA_NAME)
        assertEquals(result!!.ca, TestConstants.TEST_CA)
        assertEquals(result.certificate, TestConstants.OTHER_TEST_CERTIFICATE)
        assertEquals(result.privateKey, TestConstants.OTHER_TEST_PRIVATE_KEY)
        assertEquals(result.caName, "/some-ca")
        assertEquals(result.isCertificateAuthority, true)
        assertEquals(result.isSelfSigned, true)
        assertEquals(result.generated, true)
        assertEquals(result.isTransitional, false)
    }

    @Test
    fun findActiveVersion_whenCaDoesNotExist_throwsCorrectException() {
        val exception = StatusRuntimeException(Status.NOT_FOUND)
        `when`(client.getByNameRequest(CA_NAME, USER)).thenThrow(exception)

        Assertions.assertThatThrownBy {
            subject.findActiveVersion(CA_NAME)
        }.hasMessage(ErrorMessages.Credential.INVALID_ACCESS)
    }

    private fun createByteStringFromData(data: CertificateCredentialValue): ByteString {
        val json = objectMapper.writeValueAsString(mapOf(
            "ca" to data.ca,
            "ca_name" to data.caName,
            "certificate" to data.certificate,
            "private_key" to data.privateKey,
            "transitional" to data.isTransitional,
            "certificate_authority" to data.isCertificateAuthority,
            "self_signed" to data.isSelfSigned,
            "generated" to data.generated

        ))
        return ByteString.copyFromUtf8(json)
    }

    private fun createByteStringFromGenerationParameters(generationParams: CertificateGenerationParameters): ByteString {
        val names = generationParams.x500Principal.getName("RFC1779")
        val x500Names: MutableMap<String, String> = mutableMapOf()
        val namesArray = names.split(",")
        namesArray.forEach {
            val kv = it.split('=')
            x500Names[kv[0]] = kv[1]
        }

        val json = objectMapper.writeValueAsString(mapOf(

            "is_ca" to generationParams.isCa,
            "organization_unit" to x500Names["OU"],
            "organization" to x500Names["O"],
            "state" to x500Names["ST"],
            "country" to x500Names["C"],
            "locality" to x500Names["L"],
            "common_name" to x500Names["CN"],
            "key_length" to generationParams.keyLength,
            "duration" to generationParams.duration,
            "self_signed" to generationParams.isSelfSigned,
            "ca_name" to generationParams.caName,
            "alternative_names" to generationParams.alternativeNames,
            "key_usage" to generationParams.keyUsage,
            "extended_key_usage" to generationParams.extendedKeyUsage
        ).filterValues { it != null })
        return ByteString.copyFromUtf8(json)
    }
}

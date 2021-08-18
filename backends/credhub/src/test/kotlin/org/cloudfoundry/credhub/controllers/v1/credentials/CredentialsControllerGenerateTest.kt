package org.cloudfoundry.credhub.controllers.v1.credentials

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.PropertyNamingStrategy
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.constants.CredentialWriteMode
import org.cloudfoundry.credhub.controllers.v1.regenerate.SpyRegenerateHandler
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.credential.RsaCredentialValue
import org.cloudfoundry.credhub.credential.SshCredentialValue
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.credential.UserCredentialValue
import org.cloudfoundry.credhub.credentials.CredentialsController
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.domain.Encryptor
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters
import org.cloudfoundry.credhub.requests.CredentialRegenerateRequest
import org.cloudfoundry.credhub.requests.RsaSshGenerationParameters
import org.cloudfoundry.credhub.utils.TestConstants
import org.cloudfoundry.credhub.views.CertificateGenerationView
import org.cloudfoundry.credhub.views.CertificateView
import org.cloudfoundry.credhub.views.CredentialView
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers
import org.mockito.Mockito
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post
import org.springframework.restdocs.payload.JsonFieldType
import org.springframework.restdocs.payload.PayloadDocumentation
import org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath
import org.springframework.restdocs.payload.PayloadDocumentation.requestFields
import org.springframework.restdocs.payload.RequestFieldsSnippet
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.Security
import java.time.Instant
import java.util.UUID

@RunWith(SpringRunner::class)
class CredentialsControllerGenerateTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()
    val uuid = UUID.randomUUID()

    lateinit var mockMvc: MockMvc
    private val spyCredentialsHandler: SpyCredentialsHandler = SpyCredentialsHandler()
    private val spyRegenerateHandler: SpyRegenerateHandler = SpyRegenerateHandler()

    private val objectMapper: ObjectMapper = ObjectMapper()
    lateinit var metadata: JsonNode

    @Before
    fun setUp() {
        objectMapper.propertyNamingStrategy = PropertyNamingStrategy.SNAKE_CASE

        val credentialController = CredentialsController(
            spyCredentialsHandler,
            CEFAuditRecord(),
            spyRegenerateHandler,
            objectMapper
        )
        metadata = objectMapper.readTree("{\"description\":\"example metadata\"}")

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(credentialController, restDocumentation)

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun POST__generate_password_returns__password_credential() {
        spyCredentialsHandler.generateCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-password-name",
            "password",
            metadata,
            StringCredentialValue("some-password")
        )

        // language=json
        val requestBody =
            """
                {
                  "name": "/some-password-name",
                  "type": "password",
                  "metadata": { "description": "example metadata"}
                }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            post(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonGenerateRequestFields().and(
                        fieldWithPath("parameters.length")
                            .description("Length of the generated value (Default: 30)")
                            .type(JsonFieldType.NUMBER)
                            .optional(),
                        fieldWithPath("parameters.exclude_upper")
                            .description("Exclude upper alpha characters from generated credential value")
                            .type(JsonFieldType.BOOLEAN)
                            .optional(),
                        fieldWithPath("parameters.exclude_lower")
                            .description("Exclude lower alpha characters from generated credential value")
                            .type(JsonFieldType.BOOLEAN)
                            .optional(),
                        fieldWithPath("parameters.exclude_number")
                            .description("Exclude number characters from generated credential value")
                            .type(JsonFieldType.BOOLEAN)
                            .optional(),
                        fieldWithPath("parameters.include_special")
                            .description("Include special characters from generated credential value")
                            .type(JsonFieldType.BOOLEAN)
                            .optional()
                    )
                )
            )
            .andReturn()

        val actualGenerateRequest = spyCredentialsHandler.generateCredential__calledWith_generateRequest

        val expectedGenerateRequest = objectMapper.readValue(requestBody, BaseCredentialGenerateRequest::class.java)

        assertThat(actualGenerateRequest).isEqualTo(expectedGenerateRequest)

        val actualResponseBody = mvcResult.response.contentAsString
        // language=json
        val expectedResponseBody =
            """
              {
                  "type": "password",
                  "version_created_at": "2019-02-01T20:37:52Z",
                  "id": $uuid,
                  "name": "/some-password-name",
                  "metadata": { "description": "example metadata"},
                  "value": "some-password"
              }
            """.trimIndent()
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun POST__generate_user_returns__user_credential() {
        spyCredentialsHandler.generateCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-user-name",
            CredentialType.USER.type.toLowerCase(),
            metadata,
            UserCredentialValue("some-username", "some-password", "foo")
        )

        // language=json
        val requestBody =
            """
                {
                  "name": "/some-user-name",
                  "type": "${CredentialType.USER.type.toLowerCase()}",
                  "metadata": { "description": "example metadata"}
                }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            post(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonGenerateRequestFields().and(
                        fieldWithPath("parameters.username")
                            .description("User provided value for username")
                            .type(JsonFieldType.STRING)
                            .optional(),
                        fieldWithPath("parameters.length")
                            .description("Length of the generated value (Default: 30)")
                            .type(JsonFieldType.NUMBER)
                            .optional(),
                        fieldWithPath("parameters.exclude_upper")
                            .description("Exclude upper alpha characters from generated credential value")
                            .type(JsonFieldType.BOOLEAN)
                            .optional(),
                        fieldWithPath("parameters.exclude_lower")
                            .description("Exclude lower alpha characters from generated credential value")
                            .type(JsonFieldType.BOOLEAN)
                            .optional(),
                        fieldWithPath("parameters.exclude_number")
                            .description("Exclude number characters from generated credential value")
                            .type(JsonFieldType.BOOLEAN)
                            .optional(),
                        fieldWithPath("parameters.include_special")
                            .description("Include special characters from generated credential value")
                            .type(JsonFieldType.BOOLEAN)
                            .optional()
                    )
                )
            )
            .andReturn()

        val actualGenerateRequest = spyCredentialsHandler.generateCredential__calledWith_generateRequest

        val expectedGenerateRequest = objectMapper.readValue(requestBody, BaseCredentialGenerateRequest::class.java)

        assertThat(actualGenerateRequest).isEqualTo(expectedGenerateRequest)

        val actualResponseBody = mvcResult.response.contentAsString
        // language=json
        val expectedResponseBody =
            """
              {
                  "type": "${CredentialType.USER.type.toLowerCase()}",
                  "version_created_at": "2019-02-01T20:37:52Z",
                  "id": $uuid,
                  "name": "/some-user-name",
                  "metadata": { "description": "example metadata"},
                  "value": {
                    "username": "some-username",
                    "password": "some-password",
                    "password_hash": "foQzXY.HaydB."
                  }
              }
            """.trimIndent()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun POST__generate_certificate_returns__certificate_credential() {

        val certificateCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.TEST_PRIVATE_KEY,
            "some-ca",
            null,
            true,
            false,
            true,
            false,
            true
        )

        val encryptor = Mockito.mock(Encryptor::class.java)
        Mockito.doReturn(TestConstants.TEST_PRIVATE_KEY).`when`<Encryptor>(encryptor).decrypt(ArgumentMatchers.any())

        val certificateCredentialVersion = CertificateCredentialVersion(
            certificateCredentialValue,
            "/some-certificate-name",
            encryptor
        )
        certificateCredentialVersion.versionCreatedAt = Instant.ofEpochSecond(1549053472L)
        certificateCredentialVersion.uuid = uuid
        certificateCredentialVersion.metadata = metadata

        spyCredentialsHandler.generateCredential__returns_credentialView = CertificateGenerationView(
            certificateCredentialVersion,
            true
        )

        // language=json
        val requestBody =
            """
                {
                  "name": "/some-certificate-name",
                  "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
                  "parameters": {
                    "common_name": "some-common-name",
                    "ca": "some-ca",
                    "is_ca": true,
                    "duration": 730
                  },
                  "metadata": { "description": "example metadata"}
                }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            post(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonGenerateRequestFields().and(
                        fieldWithPath("parameters.common_name")
                            .description("Common name of generated credential value.")
                            .type(JsonFieldType.STRING)
                            .optional(),
                        fieldWithPath("parameters.alternative_names")
                            .description("Alternative names of generated credential value.")
                            .type(JsonFieldType.ARRAY)
                            .optional(),
                        fieldWithPath("parameters.organization")
                            .description("Organization of generated credential value.")
                            .type(JsonFieldType.STRING)
                            .optional(),
                        fieldWithPath("parameters.organization_unit")
                            .description("Organization Unit of generated credential value.")
                            .type(JsonFieldType.STRING)
                            .optional(),
                        fieldWithPath("parameters.locality")
                            .description("Locality/city of generated credential value.")
                            .type(JsonFieldType.STRING)
                            .optional(),
                        fieldWithPath("parameters.state")
                            .description("Locality/city of generated credential value.")
                            .type(JsonFieldType.STRING)
                            .optional(),
                        fieldWithPath("parameters.country")
                            .description("Country of generated credential value.")
                            .type(JsonFieldType.STRING)
                            .optional(),
                        fieldWithPath("parameters.key_usage")
                            .description("Key usage extensions of generated credential value.")
                            .type(JsonFieldType.ARRAY)
                            .optional(),
                        fieldWithPath("parameters.extended_key_usage")
                            .description("Extended key usage extensions of generated credential value.")
                            .type(JsonFieldType.ARRAY)
                            .optional(),
                        fieldWithPath("parameters.key_length")
                            .description("Key length of generated credential value (Default: ${CertificateGenerationRequestParameters().keyLength}). Valid key lengths are: ${CertificateGenerationRequestParameters().validKeyLengths.joinToString(", ")}")
                            .type(JsonFieldType.NUMBER)
                            .optional(),
                        fieldWithPath("parameters.duration")
                            .description("Duration in days of generated credential value (Default: ${CertificateGenerationRequestParameters().duration}). If a minimum duration is configured and is greater than this duration, the minimum duration will be used instead.")
                            .type(JsonFieldType.NUMBER)
                            .optional(),
                        fieldWithPath("parameters.ca")
                            .description("Name of certificate authority to sign of generated credential value.")
                            .type(JsonFieldType.STRING)
                            .optional(),
                        fieldWithPath("parameters.is_ca")
                            .description("Whether to generate credential value as a certificate authority.")
                            .type(JsonFieldType.BOOLEAN)
                            .optional(),
                        fieldWithPath("parameters.self_sign")
                            .description("Whether to self-sign generated credential value.")
                            .type(JsonFieldType.BOOLEAN)
                            .optional()
                    )
                )
            )
            .andReturn()

        val actualGenerateRequest = spyCredentialsHandler.generateCredential__calledWith_generateRequest

        val expectedGenerateRequest = objectMapper.readValue(requestBody, BaseCredentialGenerateRequest::class.java)

        assertThat(actualGenerateRequest).isEqualTo(expectedGenerateRequest)

        val actualResponseBody = mvcResult.response.contentAsString

        print(actualResponseBody)
        // language=json
        val expectedResponseBody =
            """
              {
                  "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
                  "version_created_at": "2019-02-01T20:37:52Z",
                  "id": $uuid,
                  "name": "/some-certificate-name",
                  "metadata": { "description": "example metadata"},
                  "transitional": false,
                  "expiry_date": "2020-09-03T18:30:11Z",
                  "certificate_authority": true,
                  "self_signed": false,
                  "generated": true,
                  "duration_overridden": true,
                  "value": {
                    "ca": "${TestConstants.TEST_CA}",
                    "certificate": "${TestConstants.TEST_CERTIFICATE}",
                    "private_key": "${TestConstants.TEST_PRIVATE_KEY}"
                  }
              }
            """.trimIndent()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun POST__generate_rsa_returns__rsa_credential() {
        spyCredentialsHandler.generateCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-rsa-name",
            CredentialType.RSA.type.toLowerCase(),
            metadata,
            RsaCredentialValue(
                TestConstants.RSA_PUBLIC_KEY_4096,
                TestConstants.PRIVATE_KEY_4096
            )
        )

        // language=json
        val requestBody =
            """
                {
                  "name": "/some-rsa-name",
                  "type": "${CredentialType.RSA.type.toLowerCase()}",
                  "metadata": { "description": "example metadata"}
                }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            post(CredentialsController.ENDPOINT)
                .credHubAuthHeader()
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonGenerateRequestFields().and(
                        fieldWithPath("parameters.key_length")
                            .description("Key length of generated credential value (Default: ${RsaSshGenerationParameters().keyLength}). Valid key lengths are: ${RsaSshGenerationParameters().validKeyLengths.joinToString(", ")}")
                            .type(JsonFieldType.NUMBER)
                            .optional()
                    )
                )
            )
            .andReturn()

        val actualGenerateRequest = spyCredentialsHandler.generateCredential__calledWith_generateRequest

        val expectedGenerateRequest = objectMapper.readValue(requestBody, BaseCredentialGenerateRequest::class.java)

        assertThat(actualGenerateRequest).isEqualTo(expectedGenerateRequest)

        val actualResponseBody = mvcResult.response.contentAsString
        // language=json
        val expectedResponseBody =
            """
              {
                  "type": "${CredentialType.RSA.type.toLowerCase()}",
                  "version_created_at": "2019-02-01T20:37:52Z",
                  "id": $uuid,
                  "name": "/some-rsa-name",
                  "metadata": { "description": "example metadata"},
                  "value": {
                    "public_key": "${TestConstants.RSA_PUBLIC_KEY_4096}",
                    "private_key": "${TestConstants.PRIVATE_KEY_4096}"
                  }
              }
            """.trimIndent()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun POST__generate_ssh_returns__ssh_credential() {
        spyCredentialsHandler.generateCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-ssh-name",
            CredentialType.SSH.type.toLowerCase(),
            metadata,
            SshCredentialValue(
                TestConstants.SSH_PUBLIC_KEY_4096,
                TestConstants.PRIVATE_KEY_4096,
                "EvI0/GIUgDjcoCzUQM+EtwnVTryNsKRd6TrHAGKJJSI"
            )
        )

        // language=json
        val requestBody =
            """
                {
                  "name": "/some-ssh-name",
                  "type": "${CredentialType.SSH.type.toLowerCase()}",
                  "metadata": { "description": "example metadata"}
                }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            post(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonGenerateRequestFields().and(
                        fieldWithPath("parameters.key_length")
                            .description("Key length of generated credential value (Default: ${RsaSshGenerationParameters().keyLength}). Valid key lengths are: ${RsaSshGenerationParameters().validKeyLengths.joinToString(", ")}")
                            .type(JsonFieldType.NUMBER)
                            .optional(),
                        fieldWithPath("parameters.ssh_comment")
                            .description("SSH comment of generated credential value")
                            .type(JsonFieldType.STRING)
                            .optional()
                    )
                )
            )
            .andReturn()

        val actualGenerateRequest = spyCredentialsHandler.generateCredential__calledWith_generateRequest

        val expectedGenerateRequest = objectMapper.readValue(requestBody, BaseCredentialGenerateRequest::class.java)

        assertThat(actualGenerateRequest).isEqualTo(expectedGenerateRequest)

        val actualResponseBody = mvcResult.response.contentAsString
        // language=json
        val expectedResponseBody =
            """
              {
                  "type": "${CredentialType.SSH.type.toLowerCase()}",
                  "version_created_at": "2019-02-01T20:37:52Z",
                  "id": $uuid,
                  "name": "/some-ssh-name",
                  "metadata": { "description": "example metadata"},
                  "value": {
                    "public_key": "${TestConstants.SSH_PUBLIC_KEY_4096}",
                    "private_key": "${TestConstants.PRIVATE_KEY_4096}",
                    "public_key_fingerprint":"EvI0/GIUgDjcoCzUQM+EtwnVTryNsKRd6TrHAGKJJSI"
                  }
              }
            """.trimIndent()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun POST__regenerate_password_returns__password_credential() {
        spyRegenerateHandler.handleRegenerate__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-password-name",
            "password",
            metadata,
            StringCredentialValue("some-password")
        )

        // language=json
        val requestBody =
            """
                {
                  "name": "/some-password-name",
                  "regenerate": true,
                  "metadata": { "description": "example metadata"}
                }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            post(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    PayloadDocumentation.requestFields(
                        PayloadDocumentation.fieldWithPath("name")
                            .description("The credential name to regenerate.")
                            .type(JsonFieldType.STRING),
                        PayloadDocumentation.fieldWithPath("regenerate")
                            .description("The credential name to regenerate.")
                            .type(JsonFieldType.BOOLEAN),
                        PayloadDocumentation.fieldWithPath("metadata.description")
                            .description("The credential metadata to add.")
                            .type(JsonFieldType.STRING)
                    )
                )
            )
            .andReturn()

        val actualRegenerateRequestName = spyRegenerateHandler.handleRegenerate__calledWith_credentialName
        val actualRegenerateRequestMetadata = spyRegenerateHandler.handleRegenerate__calledWith_credentialMetadata

        val expectedRegenerateRequest = objectMapper.readValue(requestBody, CredentialRegenerateRequest::class.java)

        assertThat(actualRegenerateRequestName).isEqualTo(expectedRegenerateRequest.name)
        assertThat(actualRegenerateRequestMetadata).isEqualTo(expectedRegenerateRequest.metadata)

        val actualResponseBody = mvcResult.response.contentAsString
        // language=json
        val expectedResponseBody =
            """
              {
                  "type": "password",
                  "version_created_at": "2019-02-01T20:37:52Z",
                  "id": $uuid,
                  "name": "/some-password-name",
                  "metadata": { "description": "example metadata"},
                  "value": "some-password"
              }
            """.trimIndent()
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    private fun getCommonGenerateRequestFields(): RequestFieldsSnippet {
        return requestFields(
            fieldWithPath("name")
                .type(JsonFieldType.STRING)
                .description("The name of the credential."),
            fieldWithPath("type")
                .type(JsonFieldType.STRING)
                .description("The type of credential."),
            fieldWithPath("mode")
                .description("Overwrite interaction mode (Default: 'converge'). Supported modes are: ${CredentialWriteMode.values().joinToString(", ")}")
                .type(JsonFieldType.STRING)
                .optional(),
            fieldWithPath("metadata")
                .description("Additional metadata of the credential.")
                .optional(),
            fieldWithPath("metadata.*")
                .ignored()
        )
    }
}

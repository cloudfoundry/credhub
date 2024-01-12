package org.cloudfoundry.credhub.controllers.v1.credentials

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.controllers.v1.regenerate.SpyRegenerateHandler
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.credential.JsonCredentialValue
import org.cloudfoundry.credhub.credential.RsaCredentialValue
import org.cloudfoundry.credhub.credential.SshCredentialValue
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.credential.UserCredentialValue
import org.cloudfoundry.credhub.credentials.CredentialsController
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.JsonHelpers.Companion.escapeNewLinesForJsonSerialization
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.requests.CertificateSetRequest
import org.cloudfoundry.credhub.requests.JsonSetRequest
import org.cloudfoundry.credhub.requests.PasswordSetRequest
import org.cloudfoundry.credhub.requests.RsaSetRequest
import org.cloudfoundry.credhub.requests.SshSetRequest
import org.cloudfoundry.credhub.requests.UserSetRequest
import org.cloudfoundry.credhub.requests.ValueSetRequest
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer
import org.cloudfoundry.credhub.utils.TestConstants
import org.cloudfoundry.credhub.views.CredentialView
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.put
import org.springframework.restdocs.payload.JsonFieldType
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
class CredentialsControllerSetTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()
    val uuid = UUID.randomUUID()

    lateinit var mockMvc: MockMvc
    private var spyCredentialsHandler: SpyCredentialsHandler = SpyCredentialsHandler()
    private var spyRegenerateHandler: SpyRegenerateHandler = SpyRegenerateHandler()
    private val objectMapper: ObjectMapper = ObjectMapper()
    lateinit var metadata: JsonNode

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpAll() {
            BouncyCastleFipsConfigurer.configure()
        }
    }

    @Before
    fun setUp() {
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
    fun PUT__set_value_credential_returns__value_credential() {
        spyCredentialsHandler.setCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-name",
            CredentialType.VALUE.type.lowercase(),
            metadata,
            StringCredentialValue("some-value")
        )

        // language=json
        val requestBody =
            """
            {
              "name": "/some-value-name",
              "type": "${CredentialType.VALUE.type.lowercase()}",
              "metadata": { "description": "example metadata"},
              "value": "some-value"
            }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            put(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonSetRequestFields().and(
                        fieldWithPath("value")
                            .description(SetRequestFieldDescription.VALUE_DESCRIPTION)
                            .type(JsonFieldType.STRING)
                    )
                )
            )
            .andReturn()

        val expectedValueSetRequest = ValueSetRequest()
        expectedValueSetRequest.value = StringCredentialValue("some-value")
        expectedValueSetRequest.name = "/some-value-name"
        expectedValueSetRequest.type = CredentialType.VALUE.type.lowercase()

        assertThat(spyCredentialsHandler.setCredential__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse =
            """
            {
              "type": "${CredentialType.VALUE.type.lowercase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-name",
              "metadata": { "description": "example metadata"},
              "value": "some-value"
            }
            """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__set_json_credential_returns__json_credential() {
        spyCredentialsHandler.setCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-name",
            CredentialType.JSON.type.lowercase(),
            metadata,
            JsonCredentialValue(
                ObjectMapper().readTree(
                    // language=json
                    """
                    {
                        "some-json-key": "some-json-value"
                    }
                    """.trimIndent()
                )
            )
        )

        // language=json
        val requestBody =
            """
            {
              "name": "/some-value-name",
              "type": "${CredentialType.JSON.type.lowercase()}",
              "metadata": { "description": "example metadata"},
              "value": {
                "some-json-key": "some-json-value"
              }
            }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            put(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonSetRequestFields().and(
                        fieldWithPath("value")
                            .description(SetRequestFieldDescription.VALUE_DESCRIPTION)
                            .type(JsonFieldType.OBJECT),
                        fieldWithPath("value.some-json-key")
                            .ignored()
                    )
                )
            )
            .andReturn()

        val expectedValueSetRequest = JsonSetRequest()
        expectedValueSetRequest.value = JsonCredentialValue(
            ObjectMapper().readTree(
                // language=json
                """
            {
                "some-json-key": "some-json-value"
            }
                """.trimIndent()
            )
        )
        expectedValueSetRequest.name = "/some-value-name"
        expectedValueSetRequest.type = CredentialType.JSON.type.lowercase()

        assertThat(spyCredentialsHandler.setCredential__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse =
            """
            {
              "type": "${CredentialType.JSON.type.lowercase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-name",
              "metadata": { "description": "example metadata"},
              "value": {
                "some-json-key": "some-json-value"
              }
            }
            """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__set_password_credential_returns__password_credential() {
        spyCredentialsHandler.setCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-password-name",
            CredentialType.PASSWORD.type.lowercase(),
            metadata,
            StringCredentialValue("some-password")
        )

        // language=json
        val requestBody =
            """
            {
              "name": "/some-password-name",
              "type": "${CredentialType.PASSWORD.type.lowercase()}",
              "metadata": { "description": "example metadata"},
              "value": "some-password"
            }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            put(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonSetRequestFields().and(
                        fieldWithPath("value")
                            .description(SetRequestFieldDescription.VALUE_DESCRIPTION)
                            .type(JsonFieldType.STRING)
                    )
                )
            )
            .andReturn()

        val expectedValueSetRequest = PasswordSetRequest()
        expectedValueSetRequest.password = StringCredentialValue("some-password")
        expectedValueSetRequest.name = "/some-password-name"
        expectedValueSetRequest.type = CredentialType.PASSWORD.type.lowercase()

        assertThat(spyCredentialsHandler.setCredential__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse =
            """
            {
              "type": "${CredentialType.PASSWORD.type.lowercase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-password-name",
              "metadata": { "description": "example metadata"},
              "value": "some-password"
            }
            """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__set_user_credential_returns__user_credential() {
        spyCredentialsHandler.setCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-user-name",
            CredentialType.USER.type.lowercase(),
            metadata,
            UserCredentialValue(
                "some-username",
                "some-password",
                "foo"
            )
        )

        // language=json
        val requestBody =
            """
            {
              "name": "/some-user-name",
              "type": "${CredentialType.USER.type.lowercase()}",
              "metadata": { "description": "example metadata"},
              "value": {
                "username": "some-username",
                "password": "some-password"
              }
            }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            put(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonSetRequestFields().and(
                        fieldWithPath("value.username")
                            .description("The username to set."),
                        fieldWithPath("value.password")
                            .description("The password to set.")
                    )
                )
            )
            .andReturn()

        val expectedValueSetRequest = UserSetRequest()
        expectedValueSetRequest.userValue = UserCredentialValue(
            "some-username",
            "some-password",
            null
        )
        expectedValueSetRequest.name = "/some-user-name"
        expectedValueSetRequest.type = CredentialType.USER.type.lowercase()

        assertThat(expectedValueSetRequest).isEqualTo(spyCredentialsHandler.setCredential__calledWith_setRequest)

        // language=json
        val expectedResponse =
            """
            {
              "type": "${CredentialType.USER.type.lowercase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-user-name",
              "metadata": { "description": "example metadata"},
              "value": {
                "username": "some-username",
                "password": "some-password",
                "password_hash": "foQzXY.HaydB."
              }
            }
            """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__set_certificate_credential_returns__certificate_credential() {
        spyCredentialsHandler.setCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-certificate-name",
            CredentialType.CERTIFICATE.type.lowercase(),
            metadata,
            CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                null,
                true,
                false,
                false,
                false
            )
        )

        // language=json
        val requestBody =
            """
            {
              "name": "/some-certificate-name",
              "type": "${CredentialType.CERTIFICATE.type.lowercase()}",
              "metadata": { "description": "example metadata"},
              "value": {
                "ca": "${escapeNewLinesForJsonSerialization(TestConstants.TEST_CA)}",
                "certificate": "${escapeNewLinesForJsonSerialization(TestConstants.TEST_CERTIFICATE)}",
                "private_key": "${escapeNewLinesForJsonSerialization(TestConstants.TEST_PRIVATE_KEY)}"
              }
            }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            put(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonSetRequestFields().and(
                        fieldWithPath("value.ca")
                            .description("Certificate authority value of credential to set. Note: 'ca' and 'ca_name' are mutually exclusive values.")
                            .type(JsonFieldType.STRING),
                        fieldWithPath("value.ca_name")
                            .description("Name of CA credential in credhub that has signed this certificate. Note: 'ca' and 'ca_name' are mutually exclusive values.")
                            .type(JsonFieldType.STRING)
                            .optional(),
                        fieldWithPath("value.certificate")
                            .description("Certificate value of credential to set.")
                            .type(JsonFieldType.STRING),
                        fieldWithPath("value.private_key")
                            .description("Private key value of credential to set.")
                            .type(JsonFieldType.STRING)
                    )
                )
            )
            .andReturn()

        val expectedValueSetRequest = CertificateSetRequest()
        expectedValueSetRequest.certificateValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.TEST_PRIVATE_KEY,
            null,
            false,
            false,
            false,
            false
        )
        expectedValueSetRequest.name = "/some-certificate-name"
        expectedValueSetRequest.type = CredentialType.CERTIFICATE.type.lowercase()

        assertThat(spyCredentialsHandler.setCredential__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse =
            """
            {
              "type": "${CredentialType.CERTIFICATE.type.lowercase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-certificate-name",
              "metadata": { "description": "example metadata"},
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}",
                "transitional": false,
                "expiry_date": "2020-09-03T18:30:11Z",
                "certificate_authority": true,
                "self_signed": false,
                "generated": false
              }
            }
            """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__set_rsa_credential_returns__rsa_credential() {
        spyCredentialsHandler.setCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-rsa-name",
            CredentialType.RSA.type.lowercase(),
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
              "type": "${CredentialType.RSA.type.lowercase()}",
              "metadata": { "description": "example metadata"},
              "value": {
                "public_key": "${escapeNewLinesForJsonSerialization(TestConstants.RSA_PUBLIC_KEY_4096)}",
                "private_key": "${escapeNewLinesForJsonSerialization(TestConstants.PRIVATE_KEY_4096)}"
              }
            }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            put(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonSetRequestFields().and(
                        fieldWithPath("value.public_key")
                            .description("Public key value of credential to set.")
                            .type(JsonFieldType.STRING),
                        fieldWithPath("value.private_key")
                            .description("Private key value of credential to set.")
                            .type(JsonFieldType.STRING)
                    )
                )
            )
            .andReturn()

        val expectedValueSetRequest = RsaSetRequest()
        expectedValueSetRequest.rsaKeyValue = RsaCredentialValue(
            TestConstants.RSA_PUBLIC_KEY_4096,
            TestConstants.PRIVATE_KEY_4096
        )
        expectedValueSetRequest.name = "/some-rsa-name"
        expectedValueSetRequest.type = CredentialType.RSA.type.lowercase()

        assertThat(spyCredentialsHandler.setCredential__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse =
            """
            {
              "type": "${CredentialType.RSA.type.lowercase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-rsa-name",
              "metadata": { "description": "example metadata"},
              "value": {
                "public_key": "${TestConstants.RSA_PUBLIC_KEY_4096}",
                "private_key": "${TestConstants.PRIVATE_KEY_4096}"
              }
            }
            """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__set_ssh_credential_returns__ssh_credential() {
        spyCredentialsHandler.setCredential__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-ssh-name",
            CredentialType.SSH.type.lowercase(),
            metadata,
            SshCredentialValue(
                TestConstants.SSH_PUBLIC_KEY_4096,
                TestConstants.PRIVATE_KEY_4096,
                null
            )
        )

        // language=json
        val requestBody =
            """
            {
              "name": "/some-ssh-name",
              "type": "${CredentialType.SSH.type.lowercase()}",
              "metadata": { "description": "example metadata" },
              "value": {
                "public_key": "${escapeNewLinesForJsonSerialization(TestConstants.SSH_PUBLIC_KEY_4096)}",
                "private_key": "${escapeNewLinesForJsonSerialization(TestConstants.PRIVATE_KEY_4096)}"
              }
            }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            put(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    getCommonSetRequestFields().and(
                        fieldWithPath("value.public_key")
                            .description("Public key value of credential to set.")
                            .type(JsonFieldType.STRING),
                        fieldWithPath("value.private_key")
                            .description("Private key value of credential to set.")
                            .type(JsonFieldType.STRING)

                    )
                )
            )
            .andReturn()

        val expectedValueSetRequest = SshSetRequest()
        expectedValueSetRequest.sshKeyValue = SshCredentialValue(
            TestConstants.SSH_PUBLIC_KEY_4096,
            TestConstants.PRIVATE_KEY_4096,
            null
        )
        expectedValueSetRequest.name = "/some-ssh-name"
        expectedValueSetRequest.type = CredentialType.SSH.type.lowercase()

        assertThat(spyCredentialsHandler.setCredential__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse =
            """
            {
              "type": "${CredentialType.SSH.type.lowercase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-ssh-name",
              "metadata": { "description": "example metadata" },
              "value": {
                "public_key": "${TestConstants.SSH_PUBLIC_KEY_4096}",
                "private_key": "${TestConstants.PRIVATE_KEY_4096}",
                "public_key_fingerprint": null
              }
            }
            """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    private fun getCommonSetRequestFields(): RequestFieldsSnippet {
        return requestFields(
            fieldWithPath("name")
                .type(JsonFieldType.STRING)
                .description("The name of the credential."),
            fieldWithPath("type")
                .type(JsonFieldType.STRING)
                .description("The type of credential."),
            fieldWithPath("metadata")
                .description("Additional metadata for credential to set.")
                .optional(),
            fieldWithPath("metadata.*")
                .ignored()
        )
    }

    private object SetRequestFieldDescription {
        val VALUE_DESCRIPTION = "Value of credential to set"
    }
}

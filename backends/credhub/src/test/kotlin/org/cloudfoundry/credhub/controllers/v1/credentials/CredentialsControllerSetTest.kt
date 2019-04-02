package org.cloudfoundry.credhub.controllers.v1.credentials

import com.fasterxml.jackson.databind.ObjectMapper
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.constants.CredentialType.JSON
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
import org.cloudfoundry.credhub.services.SpyPermissionedCredentialService
import org.cloudfoundry.credhub.utils.TestConstants
import org.cloudfoundry.credhub.views.CredentialView
import org.junit.Before
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
    lateinit var spySetHandler: SpySetHandler

    @Before
    fun setUp() {
        spySetHandler = SpySetHandler()

        val credentialController = CredentialsController(
            SpyPermissionedCredentialService(),
            SpyCredentialsHandler(),
            spySetHandler,
            SpyLegacyGenerationHandler(),
            CEFAuditRecord()
        )

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(credentialController, restDocumentation)

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun PUT__set_value_credential_returns__value_credential() {
        spySetHandler.handle__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-path",
            CredentialType.VALUE.type.toLowerCase(),
            StringCredentialValue("some-value")
        )

        // language=json
        val requestBody = """
            {
              "name": "/some-value-path",
              "type": "${CredentialType.VALUE.type.toLowerCase()}",
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
        expectedValueSetRequest.name = "/some-value-path"
        expectedValueSetRequest.type = CredentialType.VALUE.type.toLowerCase()

        assertThat(spySetHandler.handle__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse = """
            {
              "type": "${CredentialType.VALUE.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-path",
              "value": "some-value"
            }
        """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__set_json_credential_returns__json_credential() {
        spySetHandler.handle__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-path",
            JSON.type.toLowerCase(),
            JsonCredentialValue(ObjectMapper().readTree(
                // language=json
                """
                    {
                        "some-json-key": "some-json-value"
                    }
                """.trimIndent()))
        )

        // language=json
        val requestBody = """
            {
              "name": "/some-value-path",
              "type": "${CredentialType.JSON.type.toLowerCase()}",
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
        expectedValueSetRequest.value = JsonCredentialValue(ObjectMapper().readTree(
            // language=json
            """
            {
                "some-json-key": "some-json-value"
            }
            """.trimIndent()
        ))
        expectedValueSetRequest.name = "/some-value-path"
        expectedValueSetRequest.type = CredentialType.JSON.type.toLowerCase()

        assertThat(spySetHandler.handle__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse = """
            {
              "type": "${CredentialType.JSON.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-path",
              "value": {
                "some-json-key": "some-json-value"
              }
            }
        """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__set_password_credential_returns__password_credential() {
        spySetHandler.handle__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-password-path",
            CredentialType.PASSWORD.type.toLowerCase(),
            StringCredentialValue("some-password")
        )

        // language=json
        val requestBody = """
            {
              "name": "/some-password-path",
              "type": "${CredentialType.PASSWORD.type.toLowerCase()}",
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
        expectedValueSetRequest.name = "/some-password-path"
        expectedValueSetRequest.type = CredentialType.PASSWORD.type.toLowerCase()

        assertThat(spySetHandler.handle__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse = """
            {
              "type": "${CredentialType.PASSWORD.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-password-path",
              "value": "some-password"
            }
        """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__set_user_credential_returns__user_credential() {
        spySetHandler.handle__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-user-path",
            CredentialType.USER.type.toLowerCase(),
            UserCredentialValue(
                "some-username",
                "some-password",
                "foo"
            )
        )

        // language=json
        val requestBody = """
            {
              "name": "/some-user-path",
              "type": "${CredentialType.USER.type.toLowerCase()}",
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
        expectedValueSetRequest.name = "/some-user-path"
        expectedValueSetRequest.type = CredentialType.USER.type.toLowerCase()

        assertThat(spySetHandler.handle__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse = """
            {
              "type": "${CredentialType.USER.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-user-path",
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
        spySetHandler.handle__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-certificate-path",
            CredentialType.CERTIFICATE.type.toLowerCase(),
            CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                null
            )
        )

        // language=json
        val requestBody = """
            {
              "name": "/some-certificate-path",
              "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
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
            null
        )
        expectedValueSetRequest.name = "/some-certificate-path"
        expectedValueSetRequest.type = CredentialType.CERTIFICATE.type.toLowerCase()

        assertThat(spySetHandler.handle__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse = """
            {
              "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-certificate-path",
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}",
                "transitional": false,
                "expiry_date": "2018-11-21T16:25:20Z"
              }
            }
        """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun PUT__set_rsa_credential_returns__rsa_credential() {
        spySetHandler.handle__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-rsa-path",
            CredentialType.RSA.type.toLowerCase(),
            RsaCredentialValue(
                TestConstants.RSA_PUBLIC_KEY_4096,
                TestConstants.PRIVATE_KEY_4096
            )
        )

        // language=json
        val requestBody = """
            {
              "name": "/some-rsa-path",
              "type": "${CredentialType.RSA.type.toLowerCase()}",
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
        expectedValueSetRequest.name = "/some-rsa-path"
        expectedValueSetRequest.type = CredentialType.RSA.type.toLowerCase()

        assertThat(spySetHandler.handle__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse = """
            {
              "type": "${CredentialType.RSA.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-rsa-path",
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
        spySetHandler.handle__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-ssh-path",
            CredentialType.SSH.type.toLowerCase(),
            SshCredentialValue(
                TestConstants.SSH_PUBLIC_KEY_4096,
                TestConstants.PRIVATE_KEY_4096,
                null
            )
        )

        // language=json
        val requestBody = """
            {
              "name": "/some-ssh-path",
              "type": "${CredentialType.SSH.type.toLowerCase()}",
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
        expectedValueSetRequest.name = "/some-ssh-path"
        expectedValueSetRequest.type = CredentialType.SSH.type.toLowerCase()

        assertThat(spySetHandler.handle__calledWith_setRequest).isEqualTo(expectedValueSetRequest)

        // language=json
        val expectedResponse = """
            {
              "type": "${CredentialType.SSH.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-ssh-path",
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
                .description("The path that represents the credential."),
            fieldWithPath("type")
                .type(JsonFieldType.STRING)
                .description("The type of credential.")
        )
    }

    private object SetRequestFieldDescription {
        val VALUE_DESCRIPTION = "Value of credential to set"
    }
}

package org.cloudfoundry.credhub.controllers.v1.credentials

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.security.Security
import java.time.Instant
import java.util.UUID
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.constants.CredentialType.JSON
import org.cloudfoundry.credhub.controllers.v1.regenerate.SpyRegenerateHandler
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.credential.JsonCredentialValue
import org.cloudfoundry.credhub.credential.RsaCredentialValue
import org.cloudfoundry.credhub.credential.SshCredentialValue
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.credential.UserCredentialValue
import org.cloudfoundry.credhub.credentials.CredentialsController
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.utils.TestConstants
import org.cloudfoundry.credhub.views.CredentialView
import org.cloudfoundry.credhub.views.DataResponse
import org.cloudfoundry.credhub.views.FindCredentialResult
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get
import org.springframework.restdocs.request.RequestDocumentation.parameterWithName
import org.springframework.restdocs.request.RequestDocumentation.pathParameters
import org.springframework.restdocs.request.RequestDocumentation.requestParameters
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@RunWith(SpringRunner::class)
class CredentialsControllerGetTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()
    val uuid = UUID.randomUUID()

    lateinit var mockMvc: MockMvc
    lateinit var spyCredentialsHandler: SpyCredentialsHandler
    lateinit var spyRegenerateHandler: SpyRegenerateHandler
    private val objectMapper: ObjectMapper = ObjectMapper()
    lateinit var metadata: JsonNode

    @Before
    fun setUp() {
        spyCredentialsHandler = SpyCredentialsHandler()
        spyRegenerateHandler = SpyRegenerateHandler()

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
    fun GET__find_by_id__returns_value_results() {
        val uuid = UUID.randomUUID()
        spyCredentialsHandler.getCredentialVersionByUUID__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-path",
            CredentialType.VALUE.type.toLowerCase(),
            metadata,
            StringCredentialValue("some-value")
        )

        val mvcResult = mockMvc.perform(
            get("${CredentialsController.ENDPOINT}/{uuid}", uuid.toString())
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    pathParameters(
                        parameterWithName("uuid").description("The credential uuid")
                    )
                )
            ).andReturn()

        assertThat(spyCredentialsHandler.getCredentialVersionByUUID__calledWith_credentialUUID).isEqualTo(uuid.toString())
        // language=json
        val expectedResponseBody = """
            {
              "type": "value",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-path",
              "metadata": { "description": "example metadata"},
              "value": "some-value"
            }
        """.trimMargin()
        val actualResponseBody = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__find_by_id__returns_json_results() {
        val uuid = UUID.randomUUID()
        spyCredentialsHandler.getCredentialVersionByUUID__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-path",
            JSON.type.toLowerCase(),
            metadata,
            JsonCredentialValue(ObjectMapper().readTree(
                // language=json
                """
                    {
                        "some-json-key": "some-json-value"
                    }
                """.trimIndent())
            )
        )

        val mvcResult = mockMvc.perform(
            get("${CredentialsController.ENDPOINT}/{uuid}", uuid.toString())
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    pathParameters(
                        parameterWithName("uuid").description("The credential uuid")
                    )
                )
            ).andReturn()

        assertThat(spyCredentialsHandler.getCredentialVersionByUUID__calledWith_credentialUUID).isEqualTo(uuid.toString())
        // language=json
        val expectedResponseBody = """
            {
              "type": "${CredentialType.JSON.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-path",
              "metadata": { "description": "example metadata"},
              "value": {
                "some-json-key": "some-json-value"
              }
            }
        """.trimMargin()
        val actualResponseBody = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__find_by_id__returns_password_results() {
        val uuid = UUID.randomUUID()
        spyCredentialsHandler.getCredentialVersionByUUID__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-path",
            CredentialType.PASSWORD.type.toLowerCase(),
            metadata,
            StringCredentialValue("some-password")
        )

        val mvcResult = mockMvc.perform(
            get("${CredentialsController.ENDPOINT}/{uuid}", uuid.toString())
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    pathParameters(
                        parameterWithName("uuid").description("The credential uuid")
                    )
                )
            ).andReturn()

        assertThat(spyCredentialsHandler.getCredentialVersionByUUID__calledWith_credentialUUID).isEqualTo(uuid.toString())
        // language=json
        val expectedResponseBody = """
            {
              "type": "${CredentialType.PASSWORD.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-path",
              "metadata": { "description": "example metadata"},
              "value": "some-password"
            }
        """.trimMargin()

        val actualResponseBody = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__find_by_id__returns_user_results() {
        val uuid = UUID.randomUUID()
        spyCredentialsHandler.getCredentialVersionByUUID__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-path",
            CredentialType.USER.type.toLowerCase(),
            metadata,
            UserCredentialValue(
                "some-username",
                "some-password",
                "foo"
            )
        )

        val mvcResult = mockMvc.perform(
            get("${CredentialsController.ENDPOINT}/{uuid}", uuid.toString())
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    pathParameters(
                        parameterWithName("uuid").description("The credential uuid")
                    )
                )
            ).andReturn()

        assertThat(spyCredentialsHandler.getCredentialVersionByUUID__calledWith_credentialUUID).isEqualTo(uuid.toString())
        // language=json
        val expectedResponseBody = """
            {
              "type": "${CredentialType.USER.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-path",
              "metadata": { "description": "example metadata"},
              "value": {
                "username": "some-username",
                "password": "some-password",
                "password_hash": "foQzXY.HaydB."
              }
            }
        """.trimMargin()

        val actualResponseBody = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__find_by_id__returns_certificate_results() {
        val uuid = UUID.randomUUID()
        spyCredentialsHandler.getCredentialVersionByUUID__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-path",
            CredentialType.CERTIFICATE.type.toLowerCase(),
            metadata,
            CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                null,
                true,
                false,
                    true,
                false
            )
        )

        val mvcResult = mockMvc.perform(
            get("${CredentialsController.ENDPOINT}/{uuid}", uuid.toString())
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    pathParameters(
                        parameterWithName("uuid").description("The credential uuid")
                    )
                )
            ).andReturn()

        assertThat(spyCredentialsHandler.getCredentialVersionByUUID__calledWith_credentialUUID).isEqualTo(uuid.toString())
        // language=json
        val expectedResponseBody = """
            {
              "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-path",
              "metadata": { "description": "example metadata"},
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}",
                "transitional": false,
                "expiry_date": "2020-09-03T18:30:11Z",
                "certificate_authority": true,
                "self_signed": false,
                "generated": true
              }
            }
        """.trimMargin()

        val actualResponseBody = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__find_by_id__WhenGeneratedIsNull_returns_certificate_results() {
        val uuid = UUID.randomUUID()
        spyCredentialsHandler.getCredentialVersionByUUID__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-path",
            CredentialType.CERTIFICATE.type.toLowerCase(),
            metadata,
            CertificateCredentialValue(
                TestConstants.TEST_CA,
                TestConstants.TEST_CERTIFICATE,
                TestConstants.TEST_PRIVATE_KEY,
                null,
                true,
                false,
                null,
                false
            )
        )

        val mvcResult = mockMvc.perform(
            get("${CredentialsController.ENDPOINT}/{uuid}", uuid.toString())
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)).andReturn()

        assertThat(spyCredentialsHandler.getCredentialVersionByUUID__calledWith_credentialUUID).isEqualTo(uuid.toString())
        // language=json
        val expectedResponseBody = """
            {
              "type": "${CredentialType.CERTIFICATE.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-path",
              "metadata": { "description": "example metadata"},
              "value": {
                "ca": "${TestConstants.TEST_CA}",
                "certificate": "${TestConstants.TEST_CERTIFICATE}",
                "private_key": "${TestConstants.TEST_PRIVATE_KEY}",
                "transitional": false,
                "expiry_date": "2020-09-03T18:30:11Z",
                "certificate_authority": true,
                "self_signed": false
              }
            }
        """.trimMargin()

        val actualResponseBody = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__find_by_id__returns_rsa_results() {
        val uuid = UUID.randomUUID()
        spyCredentialsHandler.getCredentialVersionByUUID__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-path",
            CredentialType.RSA.type.toLowerCase(),
            metadata,
            RsaCredentialValue(
                TestConstants.RSA_PUBLIC_KEY_4096,
                TestConstants.PRIVATE_KEY_4096
            )
        )

        val mvcResult = mockMvc.perform(
            get("${CredentialsController.ENDPOINT}/{uuid}", uuid.toString())
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    pathParameters(
                        parameterWithName("uuid").description("The credential uuid")
                    )
                )
            ).andReturn()

        assertThat(spyCredentialsHandler.getCredentialVersionByUUID__calledWith_credentialUUID).isEqualTo(uuid.toString())
        // language=json
        val expectedResponseBody = """
            {
              "type": "${CredentialType.RSA.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-path",
              "metadata": { "description": "example metadata"},
              "value": {
                "public_key": "${TestConstants.RSA_PUBLIC_KEY_4096}",
                "private_key": "${TestConstants.PRIVATE_KEY_4096}"
              }
            }
        """.trimMargin()

        val actualResponseBody = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__find_by_id__returns_ssh_results() {
        val uuid = UUID.randomUUID()
        spyCredentialsHandler.getCredentialVersionByUUID__returns_credentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-path",
            CredentialType.SSH.type.toLowerCase(),
            metadata,
            SshCredentialValue(
                TestConstants.SSH_PUBLIC_KEY_4096,
                TestConstants.PRIVATE_KEY_4096,
                null
            )
        )

        val mvcResult = mockMvc.perform(
            get("${CredentialsController.ENDPOINT}/{uuid}", uuid.toString())
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    pathParameters(
                        parameterWithName("uuid").description("The credential uuid")
                    )
                )
            ).andReturn()

        assertThat(spyCredentialsHandler.getCredentialVersionByUUID__calledWith_credentialUUID).isEqualTo(uuid.toString())
        // language=json
        val expectedResponseBody = """
            {
              "type": "${CredentialType.SSH.type.toLowerCase()}",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$uuid",
              "name": "/some-value-path",
              "metadata": { "description": "example metadata"},
              "value": {
                "public_key": "${TestConstants.SSH_PUBLIC_KEY_4096}",
                "private_key": "${TestConstants.PRIVATE_KEY_4096}",
                "public_key_fingerprint": null
              }
            }
        """.trimMargin()

        val actualResponseBody = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__find_by_name_like__returns_results() {
        spyCredentialsHandler.findContainingName__returns_findCredentialResultList = listOf(
            FindCredentialResult(
                Instant.ofEpochSecond(1549053472L),
                "some-credential-name"
            )
        )

        val mvcResult = mockMvc.perform(
            get(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .param("name-like", "some-credential")
                .param("expires-within-days", "1")
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters(
                        parameterWithName("name-like")
                            .description("The credential name substring"),
                        parameterWithName("expires-within-days")
                            .description("The number of days the credential should expire within")
                            .optional()
                    )
                )
            )
            .andReturn()

        assertThat(spyCredentialsHandler.findContainingName__calledWith_name).isEqualTo("some-credential")
        assertThat(spyCredentialsHandler.findContainingName__calledWith_expiresWithinDays).isEqualTo("1")
        val actualResponseBody = mvcResult.response.contentAsString
        // language=json
        val expectedResponseBody = """
            {
                "credentials": [
                    {
                        "version_created_at": "2019-02-01T20:37:52Z",
                        "name": "some-credential-name"
                    }
                ]
            }
        """.trimMargin()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__find_by_path__returns_results() {
        spyCredentialsHandler.findStartingWithPath__returns_findCredentialResultList = listOf(
            FindCredentialResult(
                Instant.ofEpochSecond(1549053472L),
                "some-credential-name"
            )
        )

        val mvcResult = mockMvc.perform(
            get(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .param("path", "some-credential-path")
                .param("expires-within-days", "1")
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters(
                        parameterWithName("path")
                            .description("The credential path"),
                        parameterWithName("expires-within-days")
                            .description("The number of days the credential should expire within")
                            .optional()
                    )
                )
            )
            .andReturn()

        assertThat(spyCredentialsHandler.findStartingWithPath__calledWith_path).isEqualTo("some-credential-path")
        assertThat(spyCredentialsHandler.findStartingWithPath__calledWith_expiresWithinDays).isEqualTo("1")
        val actualResponseBody = mvcResult.response.contentAsString
        // language=json
        val expectedResponseBody = """
            {
                "credentials": [
                    {
                        "version_created_at": "2019-02-01T20:37:52Z",
                        "name": "some-credential-name"
                    }
                ]
            }
        """.trimMargin()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__get_by_name__returns_results() {
        spyCredentialsHandler.getCurrentCredentialVersions__returns_dataResponse = DataResponse(
            listOf(
                CredentialView(
                    Instant.ofEpochSecond(1549053472L),
                    uuid,
                    "/some-name",
                    CredentialType.VALUE.type.toLowerCase(),
                    metadata,
                    StringCredentialValue("some-value")
                )
            )
        )

        val mvcResult = mockMvc.perform(
            get(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .param("name", "/some-name")
                .param("current", "true")
        )
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters(
                        parameterWithName("name")
                            .description("The name of the credential."),
                        parameterWithName("versions")
                            .optional()
                            .description("The number of versions to return. Note: this cannot be combined with 'current'. Defaults to all versions if not provided."),
                        parameterWithName("current")
                            .optional()
                            .description("Only return the latest version of a credential. Note: this cannot be combined with 'versions'.")
                    )
                )
            ).andReturn()

        assertThat(spyCredentialsHandler.getCurrentCredentialVersions__calledWith_credentialName).isEqualTo("/some-name")

        val actualResponse = mvcResult.response.contentAsString
        // language=json
        val expectedResponseBody = """
            {
              "data": [
                  {
                      "type": "value",
                      "version_created_at": "2019-02-01T20:37:52Z",
                      "id": "$uuid",
                      "name": "/some-name",
                      "metadata": { "description": "example metadata"},
                      "value": "some-value"
                  }
              ]
            }
        """.trimMargin()

        JSONAssert.assertEquals(actualResponse, expectedResponseBody, true)
    }
}

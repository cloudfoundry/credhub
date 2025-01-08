package org.cloudfoundry.credhub.controllers.v1.regenerate

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.regenerate.RegenerateController
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer
import org.cloudfoundry.credhub.views.BulkRegenerateResults
import org.cloudfoundry.credhub.views.CredentialView
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.payload.JsonFieldType
import org.springframework.restdocs.payload.PayloadDocumentation
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.Security
import java.time.Instant
import java.util.UUID

@RunWith(SpringRunner::class)
class RegenerateControllerTest {
    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    private lateinit var spyRegenerateHandler: SpyRegenerateHandler
    private lateinit var mockMvc: MockMvc

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
    fun beforeEach() {
        spyRegenerateHandler = SpyRegenerateHandler()
        val regenerateController = RegenerateController(spyRegenerateHandler)

        metadata = objectMapper.readTree("{\"description\":\"example metadata\"}")

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(regenerateController, restDocumentation)
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun postRegenerateReturnsResults() {
        val randomUUID = UUID.randomUUID()
        spyRegenerateHandler.handleregenerateReturnsCredentialview =
            CredentialView(
                Instant.ofEpochSecond(1549053472L),
                randomUUID,
                "/some-name",
                CredentialType.VALUE.type.lowercase(),
                metadata,
                StringCredentialValue("some-value"),
            )

        val actualResponse =
            mockMvc
                .perform(
                    post("/api/v1/regenerate")
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(
                            """
                            {
                                "name": "/some-name",
                                "metadata": { "some": "example metadata"}
                            }
                            """.trimIndent(),
                        ),
                ).andExpect(status().isOk)
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        PayloadDocumentation.requestFields(
                            PayloadDocumentation
                                .fieldWithPath("name")
                                .description("The credential name to regenerate.")
                                .type(JsonFieldType.STRING),
                            PayloadDocumentation
                                .fieldWithPath("metadata")
                                .description("Additional metadata of the credential.")
                                .optional(),
                            PayloadDocumentation
                                .fieldWithPath("metadata.*")
                                .ignored(),
                        ),
                    ),
                ).andReturn()
                .response

        // language=json
        val expectedResponse =
            """
            {
              "type": "value",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": "$randomUUID",
              "name": "/some-name",
              "metadata": { "description": "example metadata"},
              "value": "some-value"
            }
            """.trimIndent()

        JSONAssert.assertEquals(expectedResponse, actualResponse.contentAsString, true)

        assertThat(spyRegenerateHandler.handleRegenerateCalledWithCredentialName, equalTo("/some-name"))
    }

    @Test
    fun postBulkregenerateReturnsResults() {
        spyRegenerateHandler.handleBulkRegenerateReturnsBulkRegenerateResults =
            {
                val bulkRegenerateResults = BulkRegenerateResults()
                bulkRegenerateResults.setRegeneratedCredentials(
                    mutableSetOf(
                        "/some-credential-name",
                        "/some-other-credential-name",
                    ),
                )

                bulkRegenerateResults
            }()

        val actualResponse =
            mockMvc
                .perform(
                    post("/api/v1/bulk-regenerate")
                        .credHubAuthHeader()
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(
                            """
                            {
                                "signed_by": "/some-ca"
                            }
                            """.trimIndent(),
                        ),
                ).andExpect(status().isOk)
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        PayloadDocumentation.requestFields(
                            PayloadDocumentation
                                .fieldWithPath("signed_by")
                                .description("The name of the CA that signs regenerated certificates.")
                                .type(JsonFieldType.STRING),
                        ),
                    ),
                ).andReturn()
                .response

        // language=json
        val expectedResponse =
            """
            {
              "regenerated_credentials": [
                "/some-credential-name",
                "/some-other-credential-name"
              ]
            }
            """.trimIndent()

        JSONAssert.assertEquals(expectedResponse, actualResponse.contentAsString, true)

        assertThat(spyRegenerateHandler.handleBulkRegenerateCalledWithSignerName, equalTo("/some-ca"))
    }
}

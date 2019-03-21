package org.cloudfoundry.credhub.controllers.v1

import org.assertj.core.api.Assertions.assertThat
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.credentials.CredentialsController
import org.cloudfoundry.credhub.handlers.DummyCredentialsHandler
import org.cloudfoundry.credhub.handlers.SpyLegacyGenerationHandler
import org.cloudfoundry.credhub.handlers.SpySetHandler
import org.cloudfoundry.credhub.requests.ValueSetRequest
import org.cloudfoundry.credhub.services.SpyPermissionedCredentialService
import org.cloudfoundry.credhub.testhelpers.MockMvcFactory
import org.cloudfoundry.credhub.views.CredentialView
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
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.put
import org.springframework.restdocs.request.RequestDocumentation.parameterWithName
import org.springframework.restdocs.request.RequestDocumentation.requestParameters
import org.springframework.restdocs.snippet.Attributes.key
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.time.Instant
import java.util.*
import java.util.stream.Collectors


@RunWith(SpringRunner::class)
class CredentialsControllerTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()
    val uuid = UUID.randomUUID()

    lateinit var mockMvc: MockMvc
    lateinit var spyPermissionedCredentialService: SpyPermissionedCredentialService
    lateinit var spyLegacyGenerationHandler : SpyLegacyGenerationHandler
    lateinit var spySetHandler : SpySetHandler

    @Before
    fun setUp() {
        spyPermissionedCredentialService = SpyPermissionedCredentialService()
        spyLegacyGenerationHandler = SpyLegacyGenerationHandler()
        spySetHandler = SpySetHandler()

        val credentialController = CredentialsController(
            spyPermissionedCredentialService,
            DummyCredentialsHandler(),
            spySetHandler,
            spyLegacyGenerationHandler,
            CEFAuditRecord()
        )

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(credentialController, restDocumentation)
    }

    @Test
    fun POST__generate_returns__credential() {
        spyLegacyGenerationHandler.auditedHandlePostRequest_returns = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-password-name",
            "password",
            StringCredentialValue("some-password")
        )

        //language=json
        val requestBody =
            """
                {
                  "name": "/some-password-name",
                  "type": "password"
                }
            """.trimIndent()

        val mvcResult = mockMvc.perform(
            post(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer [some-token]")
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document("{methodName}")
            )
            .andReturn()

        val actualInputStream = BufferedReader(InputStreamReader(spyLegacyGenerationHandler.auditedHandlePostRequest_calledWithInputStream))
            .lines().collect(Collectors.joining("\n"))

        val expectedInputStream = BufferedReader(InputStreamReader(ByteArrayInputStream(requestBody.toByteArray())))
            .lines().collect(Collectors.joining("\n"))

        assertThat(actualInputStream).isEqualTo(expectedInputStream)

        val actualResponseBody = mvcResult.response.contentAsString
        //language=json
        val expectedResponseBody =
            """
              {
                  "type": "password",
                  "version_created_at": "2019-02-01T20:37:52Z",
                  "id": ${uuid.toString()},
                  "name": "/some-password-name",
                  "value": "some-password"
              }
            """.trimIndent()
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun PUT__set_credential_returns__credential() {
        spySetHandler.handle_returnsCredentialView = CredentialView(
            Instant.ofEpochSecond(1549053472L),
            uuid,
            "/some-value-name",
            "value",
            StringCredentialValue("some-value")
        )

        // language=json
        val requestBody = """
            {
              "name": "/some-value-name",
              "type": "value",
              "value": "some-value"
            }
        """.trimIndent()

        val mvcResult = mockMvc.perform(
            put(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer [some-token]")
                .content(requestBody)
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document("{methodName}")
            )
            .andReturn()

        val expectedValueSetRequest = ValueSetRequest()
        expectedValueSetRequest.value = StringCredentialValue("some-value")
        expectedValueSetRequest.name = "/some-value-name"
        expectedValueSetRequest.type = "value"

        assertThat(spySetHandler.handle_calledWithSetRequest).isEqualTo(expectedValueSetRequest)

        //language=json
        val expectedResponse = """
            {
              "type": "value",
              "version_created_at": "2019-02-01T20:37:52Z",
              "id": ${uuid.toString()},
              "name": "/some-value-name",
              "value": "some-value"
            }
        """.trimIndent()

        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }

    @Test
    fun GET__find_by_path_returns__results() {
        spyPermissionedCredentialService.return_findStartingWithPath = listOf(
            FindCredentialResult(
                Instant.ofEpochSecond(1549053472L),
                "some-credential-name"
            )
        )

        val mvcResult = mockMvc.perform(
            get(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer [some-token]")
                .param("path", "some-credential-path")
                .param("expires-within-days", "1")
        )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    "{methodName}",
                    requestParameters(
                        parameterWithName("path")
                            .description("The credential path")
                            .attributes(
                                key("default").value("none"),
                                key("required").value("yes"),
                                key("type").value("string")
                            ),
                        parameterWithName("expires-within-days")
                            .description("The number of days the credential should expire within")
                            .attributes(
                                key("default").value("none"),
                                key("required").value("no"),
                                key("type").value("string")
                            )

                    )
                )
            )
            .andReturn()

        assertThat(spyPermissionedCredentialService.findStartingWithPathCalledWithPath).isEqualTo("some-credential-path")
        assertThat(spyPermissionedCredentialService.findStartingWithPathCalledWithExpiresWithinDays).isEqualTo("1")
        val actualResponseBody = mvcResult.response.contentAsString
        //language=json
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
}

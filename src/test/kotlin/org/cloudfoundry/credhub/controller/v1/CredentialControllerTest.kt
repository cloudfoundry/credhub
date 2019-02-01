package org.cloudfoundry.credhub.controller.v1

import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.handler.DummyCredentialsHandler
import org.cloudfoundry.credhub.handler.DummyLegacyGenerationHandler
import org.cloudfoundry.credhub.handler.DummySetHandler
import org.cloudfoundry.credhub.service.SpyPermissionedCredentialService
import org.cloudfoundry.credhub.view.FindCredentialResult
import org.hamcrest.Matchers.equalTo
import org.junit.Assert.assertThat
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get
import org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint
import org.springframework.restdocs.request.RequestDocumentation.parameterWithName
import org.springframework.restdocs.request.RequestDocumentation.requestParameters
import org.springframework.restdocs.snippet.Attributes.key
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultHandlers
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder
import java.time.Instant

@RunWith(SpringRunner::class)
class CredentialControllerTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    lateinit var mockMvc: MockMvc
    lateinit var spyPermissionedCredentialService: SpyPermissionedCredentialService

    @Before
    fun setUp() {
        spyPermissionedCredentialService = SpyPermissionedCredentialService()

        val credentialController = CredentialsController(
                spyPermissionedCredentialService,
                DummyCredentialsHandler(),
                DummySetHandler(),
                DummyLegacyGenerationHandler(),
                CEFAuditRecord()
        )

        mockMvc = MockMvcBuilders
                .standaloneSetup(credentialController)
                .alwaysDo<StandaloneMockMvcBuilder>(MockMvcResultHandlers.print())
                .apply<StandaloneMockMvcBuilder>(
                        documentationConfiguration(this.restDocumentation)
                                .operationPreprocessors()
                                .withRequestDefaults(prettyPrint())
                                .withResponseDefaults(prettyPrint())
                )
                .build()
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

        assertThat(spyPermissionedCredentialService.findStartingWithPathCalledWithPath, equalTo("some-credential-path"))
        assertThat(spyPermissionedCredentialService.findStartingWithPathCalledWithExpiresWithinDays, equalTo("1"))
        val actualResponseBody = mvcResult.response.contentAsString
        val expectedResponseBody = """
            {
                "credentials": [
                    {
                        "versionCreatedAt": 1549053472.000000000,
                        "name": "some-credential-name"
                    }
                ]
            }
        """.trimMargin()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }
}
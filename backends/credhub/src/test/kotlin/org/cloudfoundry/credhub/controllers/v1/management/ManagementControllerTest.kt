package org.cloudfoundry.credhub.controllers.v1.management

import org.assertj.core.api.Assertions.assertThat
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.management.ManagementController
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post
import org.springframework.restdocs.payload.JsonFieldType
import org.springframework.restdocs.payload.PayloadDocumentation
import org.springframework.restdocs.payload.PayloadDocumentation.requestFields
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers

@RunWith(SpringRunner::class)
class ManagementControllerTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    lateinit var mockMvc: MockMvc
    lateinit var spyManagementService: SpyManagementService

    @Before
    fun setUp() {

        spyManagementService = SpyManagementService()

        val managementController = ManagementController(spyManagementService)
        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(managementController, restDocumentation)
    }

    @Test
    fun GET__management_mode__returns_result() {
        spyManagementService.isReadOnlyMode__returns_boolean = false

        val mvcResult = mockMvc.perform(
            get(ManagementController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
        )
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                MockMvcRestDocumentation.document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER
                )
            ).andReturn()

        val expectedResponseBody = """
            {
                "read_only_mode": false
            }
        """.trimIndent()
        val actualResponseBody = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun POST__management_mode__returns_result() {
        val mvcResult = mockMvc.perform(
            post(ManagementController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader()
                .content(
                    """
                        {
                            "read_only_mode": true
                        }
                    """.trimIndent()
                )
        )
            .andExpect(MockMvcResultMatchers.status().isOk)
            .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                MockMvcRestDocumentation.document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestFields(
                        PayloadDocumentation.fieldWithPath("read_only_mode")
                            .description("Enables / disables read only mode for the entire API.")
                            .type(JsonFieldType.BOOLEAN)
                    )
                )
            ).andReturn()

        assertThat(spyManagementService.toggleReadOnlyMode__calledWith_shouldUseReadOnlyMode).isEqualTo(true)

        val expectedResponseBody = """
            {
                "read_only_mode": true
            }
        """.trimIndent()
        val actualResponseBody = mvcResult.response.contentAsString
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }
}

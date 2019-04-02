package org.cloudfoundry.credhub.controllers.v1.regenerate

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.regenerate.RegenerateController
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
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

@RunWith(SpringRunner::class)
class RegenerateControllerTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    private lateinit var spyRegenerateHandler: SpyRegenerateHandler
    private lateinit var mockMvc: MockMvc

    @Before
    fun beforeEach() {
        spyRegenerateHandler = SpyRegenerateHandler()
        val regenerateController = RegenerateController(spyRegenerateHandler)

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(regenerateController, restDocumentation)
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun POST__regenerate__returns_results() {
        mockMvc
            .perform(
                post("/api/v1/regenerate")
                    .header("Authorization", "Bearer [some-token]")
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {
                            "name": "/picard"
                        }
                    """.trimIndent()
                    )
            )
            .andExpect(status().isOk)
            .andDo(
                    document(
                            CredHubRestDocs.DOCUMENT_IDENTIFIER,
                            PayloadDocumentation.requestFields(
                                    PayloadDocumentation.fieldWithPath("name")
                                            .description("credential name")
                                            .type(JsonFieldType.STRING)
                            )
                    )
            ).andReturn()

        assertThat(spyRegenerateHandler.handleRegenerate__calledWith_credentialName, equalTo("/picard"))
    }

    @Test
    fun POST__bulkregenerate__returns_results() {

        mockMvc
            .perform(
                post("/api/v1/bulk-regenerate")
                    .header("Authorization", "Bearer [some-token]")
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {
                            "signed_by": "/some-ca"
                        }
                    """.trimIndent())
            )
            .andExpect(status().isOk)
            .andDo(
                    document(
                            CredHubRestDocs.DOCUMENT_IDENTIFIER,
                            PayloadDocumentation.requestFields(
                                    PayloadDocumentation.fieldWithPath("signed_by")
                                            .description("CA name")
                                            .type(JsonFieldType.STRING)
                            )
                    )
            ).andReturn()

        assertThat(spyRegenerateHandler.handleBulkRegenerate_calledWith_signerName, equalTo("/some-ca"))
    }
}

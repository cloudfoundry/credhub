package org.cloudfoundry.credhub.controllers.v1.credentials

import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.controllers.v1.regenerate.SpyRegenerateHandler
import org.cloudfoundry.credhub.credentials.CredentialsController
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.http.MediaType
import org.springframework.restdocs.ManualRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete
import org.springframework.restdocs.request.RequestDocumentation.parameterWithName
import org.springframework.restdocs.request.RequestDocumentation.queryParameters
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import tools.jackson.databind.json.JsonMapper
import java.security.Security

class CredentialsControllerDeleteTest {
    private val restDocumentation = ManualRestDocumentation()

    lateinit var mockMvc: MockMvc
    var spyCredentialsHandler: SpyCredentialsHandler = SpyCredentialsHandler()
    var spyRegenerateHandler: SpyRegenerateHandler = SpyRegenerateHandler()
    private val objectMapper: JsonMapper = JsonMapper.builder().build()

    companion object {
        @BeforeAll
        @JvmStatic
        fun setUpAll() {
            BouncyCastleFipsConfigurer.configure()
        }
    }

    @BeforeEach
    fun setUp() {
        restDocumentation.beforeTest(javaClass, javaClass.simpleName)
        val credentialController =
            CredentialsController(
                spyCredentialsHandler,
                CEFAuditRecord(),
                spyRegenerateHandler,
                objectMapper,
            )
        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(credentialController, restDocumentation)

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @AfterEach
    fun tearDown() {
        restDocumentation.afterTest()
    }

    @Test
    fun deleteCredential_returns__void() {
        val mvcResult =
            mockMvc
                .perform(
                    delete("${CredentialsController.ENDPOINT}?name=/some-credential-name")
                        .credHubAuthHeader()
                        .contentType(MediaType.APPLICATION_JSON)
                        .param("name", "/some-credential-name"),
                ).andExpect(status().isNoContent())
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        queryParameters(
                            parameterWithName("name")
                                .description("The credential name"),
                        ),
                    ),
                ).andReturn()

        assertThat(spyCredentialsHandler.deletecredentialCalledwithCredentialname).contains("/some-credential-name")
        val actualResponseBody = mvcResult.response.contentAsString

        assertThat(actualResponseBody).isEqualTo("")
    }
}

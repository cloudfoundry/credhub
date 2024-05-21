package org.cloudfoundry.credhub.controllers.v1.credentials

import com.fasterxml.jackson.databind.ObjectMapper
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.controllers.v1.regenerate.SpyRegenerateHandler
import org.cloudfoundry.credhub.credentials.CredentialsController
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete
import org.springframework.restdocs.request.RequestDocumentation.parameterWithName
import org.springframework.restdocs.request.RequestDocumentation.requestParameters
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.Security

class CredentialsControllerDeleteTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    lateinit var mockMvc: MockMvc
    var spyCredentialsHandler: SpyCredentialsHandler = SpyCredentialsHandler()
    var spyRegenerateHandler: SpyRegenerateHandler = SpyRegenerateHandler()
    private val objectMapper: ObjectMapper = ObjectMapper()

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
            objectMapper,
        )
        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(credentialController, restDocumentation)

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun DELETE__credential_returns__void() {
        val mvcResult = mockMvc.perform(
            delete("${CredentialsController.ENDPOINT}?name=/some-credential-name")
                .credHubAuthHeader()
                .contentType(MediaType.APPLICATION_JSON)
                .param("name", "/some-credential-name"),
        )
            .andExpect(status().isNoContent())
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters(
                        parameterWithName("name")
                            .description("The credential name"),
                    ),
                ),
            )
            .andReturn()

        assertThat(spyCredentialsHandler.deleteCredential__calledWith_credentialName).contains("/some-credential-name")
        val actualResponseBody = mvcResult.response.contentAsString

        assertThat(actualResponseBody).isEqualTo("")
    }
}

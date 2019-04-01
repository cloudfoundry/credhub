package org.cloudfoundry.credhub.controllers.v1.credentials

import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.credentials.CredentialsController
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.services.SpyPermissionedCredentialService
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete
import org.springframework.restdocs.request.RequestDocumentation
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import java.security.Security

class CredentialsControllerDeleteTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    lateinit var mockMvc: MockMvc
    lateinit var spyCredentialsHandler: SpyCredentialsHandler

    @Before
    fun setUp() {
        spyCredentialsHandler = SpyCredentialsHandler()

        val credentialController = CredentialsController(
            SpyPermissionedCredentialService(),
            spyCredentialsHandler,
            SpySetHandler(),
            SpyLegacyGenerationHandler(),
            CEFAuditRecord()
        )

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(credentialController, restDocumentation)

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun DELETE__credential_returns__void() {
        val mvcResult = mockMvc.perform(
            delete(CredentialsController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer [some-token]")
                .param("name", "/some-credential-path")
        )
            .andExpect(MockMvcResultMatchers.status().isNoContent())
            .andDo(
                MockMvcRestDocumentation.document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    RequestDocumentation.requestParameters(
                        RequestDocumentation.parameterWithName("name")
                            .description("The credential path")
                    )
                )
            )
            .andReturn()

        assertThat(spyCredentialsHandler.deleteCredential_calledWithCredentialName).isEqualTo("/some-credential-path")
        val actualResponseBody = mvcResult.response.contentAsString

        assertThat(actualResponseBody).isEqualTo("")
    }
}

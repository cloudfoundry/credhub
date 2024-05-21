package org.cloudfoundry.credhub.controllers.v1.versions

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer
import org.cloudfoundry.credhub.utils.VersionProvider
import org.cloudfoundry.credhub.versions.VersionController
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import java.security.Security

class VersionControllerTest {
    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    lateinit var mockMvc: MockMvc
    lateinit var versionProvider: VersionProvider

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpAll() {
            BouncyCastleFipsConfigurer.configure()
        }
    }

    @Before
    fun setUp() {
        versionProvider = Mockito.mock(VersionProvider::class.java)

        val versionController = VersionController(versionProvider)

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(versionController, restDocumentation)

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun GET__version__returns_version() {
        Mockito.`when`(versionProvider.currentVersion()).thenReturn("x.x.x")
        val mvcResult = mockMvc.perform(
            RestDocumentationRequestBuilders.get(VersionController.ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .credHubAuthHeader(),
        ).andExpect(MockMvcResultMatchers.status().isOk)
            .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                MockMvcRestDocumentation.document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                ),
            ).andReturn()

        // language=json
        val expectedResponse =
            """
            {
              "version": "x.x.x"
            }
            """.trimIndent()
        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponse, true)
    }
}

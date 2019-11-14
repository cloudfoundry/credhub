package org.cloudfoundry.credhub.controllers.v1.info

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.info.InfoController
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.Security

@RunWith(SpringRunner::class)
class InfoControllerTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    lateinit var mockMvc: MockMvc
    lateinit var uaaUrl: String

    @Before
    fun setUp() {

        uaaUrl = "https://uaa.url.example.com"

        val infoController = InfoController(uaaUrl)

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(infoController, restDocumentation)

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun GET__info__returns_info() {
        val mvcResult = mockMvc.perform(
                get(InfoController.ENDPOINT)
                    .credHubAuthHeader()
                    .contentType(MediaType.APPLICATION_JSON)
                )
                .andExpect(status().isOk)
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andDo(
                        document(
                                CredHubRestDocs.DOCUMENT_IDENTIFIER
                        )
                ).andReturn()

        // language=json
        val expectedResponseBody = """
            {
              "app": {
                "name": "${InfoController.CREHUB_NAME}"
              },
              "auth-server": {
                "url": "$uaaUrl"
              }
            }
        """.trimIndent()
        JSONAssert.assertEquals(mvcResult.response.contentAsString, expectedResponseBody, true)
    }
}

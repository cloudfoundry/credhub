package org.cloudfoundry.credhub.controllers.v1.interpolate

import com.fasterxml.jackson.databind.ObjectMapper
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.interpolation.InterpolationController
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.Security

class InterpolateControllerTest {
    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    lateinit var mockMvc: MockMvc
    lateinit var spyInterpolationHandler: SpyInterpolationHandler

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpAll() {
            BouncyCastleFipsConfigurer.configure()
        }
    }

    @Before
    fun setUp() {
        spyInterpolationHandler = SpyInterpolationHandler()

        val interpolationController =
            InterpolationController(
                spyInterpolationHandler,
                CEFAuditRecord(),
            )

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(interpolationController, restDocumentation)

        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun postInterpolateReturnsMap() {
        // language=json
        val responseBody =
            """
            {
              "service-name": [
                {
                  "credentials": {
                    "username": "some-username",
                    "password": "some-password"
                  },
                  "label": "service-name",
                  "other-metadata": "some-other-metadata"
                }
              ]
            }
            """.trimIndent()
        val objectMapper = ObjectMapper()

        val map = objectMapper.readValue(responseBody, Map::class.java) as Map<String, Any>
        spyInterpolationHandler.interpolatecredhubreferencesReturnsMap = map

        // language=json
        val requestBody =
            """
            {
              "service-name": [
                {
                  "credentials": {
                    "credhub-ref": "/some-credhub-ref"
                  },
                  "label": "service-name",
                  "other-metadata": "some-other-metadata"
                }
              ]
            }
            """.trimIndent()

        val expectedRequest = objectMapper.readValue(requestBody, Map::class.java) as Map<String, Any>

        val mvcResult =
            mockMvc
                .perform(
                    post(InterpolationController.ENDPOINT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .credHubAuthHeader()
                        .content(requestBody),
                ).andExpect(status().isOk)
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    ),
                ).andReturn()

        assertThat(spyInterpolationHandler.interpolatecredhubreferencesCalledwithServicesmap).isEqualTo(expectedRequest)
        JSONAssert.assertEquals(mvcResult.response.contentAsString, responseBody, true)
    }
}

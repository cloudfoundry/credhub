package org.cloudfoundry.credhub.controllers.v1.health

import org.cloudfoundry.credhub.health.HealthController
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@Deprecated(
    message = "No longer needed after CredHub 2.2 because we have Spring Actuator"
)
@RunWith(SpringRunner::class)
class HealthControllerTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    private lateinit var mockMvc: MockMvc
    private lateinit var healthController: HealthController

    @Before
    fun setUp() {
        healthController = HealthController()

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(
            healthController,
            restDocumentation,
            disableAuth = true
        )
    }

    @Test
    fun GET__health__returns_status() {
        val mvcResult = mockMvc
            .perform(
                get(HealthController.ENDPOINT)
            )
            .andExpect(status().isOk)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER
                )
            )
            .andReturn()

        val expectedResponseBody = """
            {
                "status": "UP"
            }
        """.trimIndent()

        val actualResponseBody = mvcResult.response.contentAsString

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }
}

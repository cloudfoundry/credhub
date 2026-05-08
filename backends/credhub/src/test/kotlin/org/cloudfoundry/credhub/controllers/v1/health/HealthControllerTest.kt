package org.cloudfoundry.credhub.controllers.v1.health

import org.cloudfoundry.credhub.health.HealthController
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInfo
import org.junit.jupiter.api.extension.ExtendWith
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.restdocs.ManualRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@Deprecated(
    message = "No longer needed after CredHub 2.2 because we have Spring Actuator",
)
@ExtendWith(SpringExtension::class)
class HealthControllerTest {
    private val restDocumentation = ManualRestDocumentation()

    private lateinit var mockMvc: MockMvc
    private lateinit var healthController: HealthController

    @BeforeEach
    fun setUp(testInfo: TestInfo) {
        restDocumentation.beforeTest(javaClass, testInfo.testMethod.get().name)
        healthController = HealthController()

        mockMvc =
            MockMvcFactory.newSpringRestDocMockMvc(
                healthController,
                restDocumentation,
                disableAuth = true,
            )
    }

    @AfterEach
    fun tearDown() {
        restDocumentation.afterTest()
    }

    @Test
    fun getHealthReturnsStatus() {
        val mvcResult =
            mockMvc
                .perform(
                    get(HealthController.ENDPOINT),
                ).andExpect(status().isOk)
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    ),
                ).andReturn()

        val expectedResponseBody =
            """
            {
                "status": "UP"
            }
            """.trimIndent()

        val actualResponseBody = mvcResult.response.contentAsString

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }
}

package org.cloudfoundry.credhub.controllers.v1

import org.cloudfoundry.credhub.health.HealthController
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders

@Deprecated(
    message = "No longer needed after CredHub 2.2 because we have Spring Actuator"
)
@RunWith(SpringRunner::class)
class HealthControllerTest {

    private lateinit var mockMvc: MockMvc

    @Before
    fun setUp() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(
                    HealthController()
                )
                .build()
    }

    @Test
    fun `should respond with a 200 and "UP" when CredHub is healthy`() {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"status\":\"UP\"}"))
    }
}

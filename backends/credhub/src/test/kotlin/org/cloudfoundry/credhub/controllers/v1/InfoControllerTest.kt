package org.cloudfoundry.credhub.controllers.v1

import org.cloudfoundry.credhub.info.InfoController
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.http.MediaType
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders

@RunWith(SpringRunner::class)
class InfoControllerTest {

    private lateinit var mockMvc: MockMvc

    @Before
    fun setUp() {
        mockMvc = MockMvcBuilders
            .standaloneSetup(
                InfoController("https://uaa.url.example.com")
            )
            .build()
    }

    @Test
    fun `should respond with application info`() {
        mockMvc.perform(get("/info"))
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.auth-server.url").value("https://uaa.url.example.com"))
            .andExpect(jsonPath("$.app.name").value("CredHub"))
    }
}

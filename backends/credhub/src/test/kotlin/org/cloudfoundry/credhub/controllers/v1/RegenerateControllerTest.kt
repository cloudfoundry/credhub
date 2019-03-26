package org.cloudfoundry.credhub.controllers.v1

import org.cloudfoundry.credhub.AuthConstants
import org.cloudfoundry.credhub.generate.RegenerateController
import org.cloudfoundry.credhub.controllers.autodocs.v1.regenerate.SpyRegenerateHandler
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.http.MediaType
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders

@RunWith(SpringRunner::class)
class RegenerateControllerTest {

    private lateinit var spyRegenerateHandler: SpyRegenerateHandler
    private lateinit var mockMvc: MockMvc

    @Before
    fun beforeEach() {
        spyRegenerateHandler = SpyRegenerateHandler()
        val regenerateController = RegenerateController(spyRegenerateHandler)

        mockMvc = MockMvcBuilders
            .standaloneSetup(regenerateController)
            .build()
    }

    @Test
    fun `POST regenerates the password`() {
        mockMvc
            .perform(post("/api/v1/regenerate")
                .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                        "name": "/picard"
                    }
                """.trimIndent())
            )
            .andExpect(status().isOk)

        assertThat(spyRegenerateHandler.handleRegenerate_calledWithCredentialName, equalTo("/picard"))
    }

    @Test
    fun `POST regenerates all certificates signed by CA`() {

        mockMvc
            .perform(
                post("/api/v1/bulk-regenerate")
                    .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {
                            "signed_by": "/some-ca"
                        }
                    """.trimIndent())
            )
            .andExpect(status().isOk)

        assertThat(spyRegenerateHandler.handleBulkRegenerate_calledWithSignerName, equalTo("/some-ca"))
    }
}

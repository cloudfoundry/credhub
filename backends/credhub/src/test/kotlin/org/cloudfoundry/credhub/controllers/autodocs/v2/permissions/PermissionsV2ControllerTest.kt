package org.cloudfoundry.credhub.controllers.autodocs.v2.permissions

import org.assertj.core.api.Assertions.assertThat
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.permissions.PermissionsV2Controller
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.testdoubles.SpyPermissionsHandler
import org.cloudfoundry.credhub.testhelpers.CredHubRestDocs
import org.cloudfoundry.credhub.testhelpers.MockMvcFactory
import org.cloudfoundry.credhub.views.PermissionsV2View
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath
import org.springframework.restdocs.payload.PayloadDocumentation.requestFields
import org.springframework.restdocs.request.RequestDocumentation.parameterWithName
import org.springframework.restdocs.request.RequestDocumentation.requestParameters
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.util.UUID

@RunWith(SpringRunner::class)
class PermissionsV2ControllerTest {

    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    val uuid = UUID.randomUUID()

    lateinit var mockMvc: MockMvc
    lateinit var spyPermissionsHandler: SpyPermissionsHandler

    @Before
    fun setUp() {
        spyPermissionsHandler = SpyPermissionsHandler()
        val permissionsV2Controller = PermissionsV2Controller(spyPermissionsHandler)

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(permissionsV2Controller, restDocumentation)
    }

    @Test
    fun GET__permissions_by_actor_and_path__returns_a_permission() {
        val permissionsV2View = PermissionsV2View(
            "some-path",
            listOf(READ, WRITE),
            "some-actor",
            uuid
        )
        spyPermissionsHandler.setReturn_findByPathAndActor(permissionsV2View)

        val mvcResult = mockMvc
            .perform(
                get(PermissionsV2Controller.ENDPOINT)
                    .header("Authorization", "Bearer [some-token]")
                    .contentType(MediaType.APPLICATION_JSON)
                    .param("path", "some-path")
                    .param("actor", "some-actor")
            )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters(
                        parameterWithName("path")
                            .description("The credential path"),
                        parameterWithName("actor")
                            .description("The credential actor")
                    )
                )

            )
            .andReturn()

        assertThat(spyPermissionsHandler.findByPathAndActorCalledWithActor).isEqualTo("some-actor")
        assertThat(spyPermissionsHandler.findByPathAndActorCalledWithPath).isEqualTo("/some-path")
        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody = """
            {
              "path": "some-path",
              "operations": [
                "read",
                "write"
              ],
              "actor": "some-actor",
              "uuid": $uuid
            }
        """.trimIndent()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun GET__permissions_by_uuid__returns_a_permission() {
        val permissionsV2View = PermissionsV2View(
            "some-path",
            listOf(READ, WRITE),
            "some-actor",
            uuid
        )
        spyPermissionsHandler.setReturn_getPermissions(permissionsV2View)

        val mvcResult = mockMvc
            .perform(
                get("${PermissionsV2Controller.ENDPOINT}/$uuid")
                    .header("Authorization", "Bearer [some-token]")
                    .contentType(MediaType.APPLICATION_JSON)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters()
                )
            )
            .andReturn()

        assertThat(spyPermissionsHandler.getPermissionsCalledWithGuid).isEqualTo(uuid)
        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody = """
            {
              "path": "some-path",
              "operations": [
                "read",
                "write"
              ],
              "actor": "some-actor",
              "uuid": "$uuid"
            }
        """.trimIndent()
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun POST__permissions__adds_a_leading_slash() {
        val permissionsV2View = PermissionsV2View(
            "some-path",
            listOf(READ, WRITE),
            "some-actor",
            uuid
        )

        val expectedPermissionsV2Request = PermissionsV2Request(
            "/some-path",
            "some-actor",
            listOf(READ, WRITE)
        )

        spyPermissionsHandler.setReturn_writeV2Permissions(permissionsV2View)

        val mvcResult = mockMvc
            .perform(
                post(PermissionsV2Controller.ENDPOINT)
                    .header("Authorization", "Bearer [some-token]")
                    .contentType(MediaType.APPLICATION_JSON)
                    // language=json
                    .content(
                        """
                            {
                              "path": "some-path",
                              "actor": "some-actor",
                              "operations": [
                                "read",
                                "write"
                              ]
                            }
                        """.trimIndent()
                    )
            )
            .andExpect(status().isCreated())
            .andReturn()

        val actualPermissionsV2Request = spyPermissionsHandler.writeV2PermissionCalledWithRequest
        assertThat(actualPermissionsV2Request.actor).isEqualTo(expectedPermissionsV2Request.actor)
        assertThat(actualPermissionsV2Request.path).isEqualTo(expectedPermissionsV2Request.path)

        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody = """
            {
              "path": "some-path",
              "operations": [
                "read",
                "write"
              ],
              "actor": "some-actor",
              "uuid": "$uuid"
            }
        """.trimIndent()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun DELETE__permissions_by_uuid__returns_a_permission() {
        val permissionsV2View = PermissionsV2View(
            "some-path",
            listOf(READ, WRITE),
            "some-actor",
            uuid
        )
        spyPermissionsHandler.setReturn_deletePermissions(permissionsV2View)

        val mvcResult = mockMvc
            .perform(
                delete("${PermissionsV2Controller.ENDPOINT}/$uuid")
                    .header("Authorization", "Bearer [some-token]")
                    .contentType(MediaType.APPLICATION_JSON)
            )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters()
                )
            )
            .andReturn()

        assertThat(spyPermissionsHandler.deletePermissionsGuid).isEqualTo(uuid.toString())
        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody = """
            {
              "path": "some-path",
              "operations": [
                "read",
                "write"
              ],
              "actor": "some-actor",
              "uuid": "$uuid"
            }
        """.trimIndent()
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun PUT__permissions__returns_a_permission() {
        val permissionsV2View = PermissionsV2View(
            "some-path",
            listOf(READ, WRITE),
            "some-actor",
            uuid
        )
        spyPermissionsHandler.setReturn_putPermissions(permissionsV2View)

        val mvcResult = mockMvc
            .perform(
                put("${PermissionsV2Controller.ENDPOINT}/$uuid")
                    .header("Authorization", "Bearer [some-token]")
                    .contentType(MediaType.APPLICATION_JSON)
                    // language=json
                    .content("""
                        {
                          "path": "some-path",
                          "actor": "some-actor",
                          "operations": [
                            "read",
                            "write"
                          ]
                        }
                    """.trimIndent())
            )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestFields(
                        fieldWithPath("path")
                            .description("The credential path"),
                        fieldWithPath("actor").description("The credential actor"),
                        fieldWithPath("operations").description("The list of permissions to be granted")
                    )
                )
            )
            .andReturn()

        assertThat(spyPermissionsHandler.putPermissionGuid).isEqualTo(uuid.toString())
        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody = """
            {
              "path": "some-path",
              "operations": [
                "read",
                "write"
              ],
              "actor": "some-actor",
              "uuid": "$uuid"
            }
        """.trimIndent()
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun PATCH__permissions__returns_a_permission() {

        val permissionsV2View = PermissionsV2View(
            "some-path",
            listOf(READ, WRITE),
            "some-actor",
            uuid
        )

        spyPermissionsHandler.setReturn_patchPermissions(permissionsV2View)

        val mvcResult = mockMvc
            .perform(
                patch("${PermissionsV2Controller.ENDPOINT}/$uuid")
                    .header("Authorization", "Bearer [some-token]")
                    .contentType(MediaType.APPLICATION_JSON)
                    // language=json
                    .content("""
                        {
                          "operations": [
                            "read",
                            "write"
                          ]
                        }
                    """.trimIndent()
                    )
            )
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestFields(
                        fieldWithPath("operations").description("The list of permissions to be granted")
                    )
                )
            )
            .andReturn()

        assertThat(spyPermissionsHandler.patchPermissionGuid).isEqualTo(uuid.toString())
        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody = """
            {
              "path": "some-path",
              "operations": [
                "read",
                "write"
              ],
              "actor": "some-actor",
              "uuid": "$uuid"
            }
        """.trimIndent()
        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun POST__permissions__returns_a_permission() {
        val permissionsV2View = PermissionsV2View(
            "some-path",
            listOf(READ, WRITE),
            "some-actor",
            uuid
        )

        spyPermissionsHandler.setReturn_writeV2Permissions(permissionsV2View)

        val mvcResult = mockMvc
            .perform(
                post(PermissionsV2Controller.ENDPOINT)
                    .header("Authorization", "Bearer [some-token]")
                    .contentType(MediaType.APPLICATION_JSON)
                    // language=json
                    .content("""
                        {
                          "path": "some-path",
                          "actor": "some-actor",
                          "operations": [
                            "read",
                            "write"
                          ]
                        }
                    """.trimIndent())
            )
            .andExpect(status().isCreated())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestFields(
                        fieldWithPath("path").description("The credential path"),
                        fieldWithPath("actor").description("The credential actor"),
                        fieldWithPath("operations").description("The list of permissions to be granted")
                    )
                )
            )
            .andReturn()

        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody = """
            {
              "path": "some-path",
              "operations": [
                "read",
                "write"
              ],
              "actor": "some-actor",
              "uuid": "$uuid"
            }
        """.trimIndent()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }
}

package org.cloudfoundry.credhub.controllers.v2.permissions

import org.assertj.core.api.Assertions.assertThat
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.permissions.PermissionsV2Controller
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.views.PermissionsV2View
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.patch
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.put
import org.springframework.restdocs.payload.FieldDescriptor
import org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath
import org.springframework.restdocs.payload.PayloadDocumentation.requestFields
import org.springframework.restdocs.request.RequestDocumentation.parameterWithName
import org.springframework.restdocs.request.RequestDocumentation.pathParameters
import org.springframework.restdocs.request.RequestDocumentation.requestParameters
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.util.UUID

class PermissionsV2ControllerTest {
    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    val uuid = UUID.randomUUID()

    lateinit var mockMvc: MockMvc
    lateinit var spyPermissionsV2Handler: SpyPermissionsV2Handler

    @Before
    fun setUp() {
        spyPermissionsV2Handler = SpyPermissionsV2Handler()
        val permissionsV2Controller = PermissionsV2Controller(spyPermissionsV2Handler)

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(permissionsV2Controller, restDocumentation)
    }

    @Test
    fun getPermissions_v2_by_actor_and_path__returns_a_permission() {
        val permissionsV2View =
            PermissionsV2View(
                "/some-path/*",
                listOf(READ, WRITE),
                "some-actor",
                uuid,
            )
        spyPermissionsV2Handler.findbypathandactorReturns = permissionsV2View

        val mvcResult =
            mockMvc
                .perform(
                    get(PermissionsV2Controller.ENDPOINT)
                        .credHubAuthHeader()
                        .contentType(MediaType.APPLICATION_JSON)
                        .param("path", "/some-path/*")
                        .param("actor", "some-actor"),
                ).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        requestParameters(
                            parameterWithName("path")
                                .description(
                                    "The credential path. Can be either a path with an asterisk (*) at the end, or the full name of a credential.",
                                ),
                            parameterWithName("actor")
                                .description("The credential actor"),
                        ),
                    ),
                ).andReturn()

        assertThat(spyPermissionsV2Handler.findbypathandactorCalledwithActor).isEqualTo("some-actor")
        assertThat(spyPermissionsV2Handler.findbypathandactorCalledwithPath).isEqualTo("/some-path/*")
        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody =
            """
            {
              "path": "/some-path/*",
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
    fun getPermissions_v2_by_uuid__returns_a_permission() {
        val permissionsV2View =
            PermissionsV2View(
                "/some-path/*",
                listOf(READ, WRITE),
                "some-actor",
                uuid,
            )
        spyPermissionsV2Handler.permissionbyguidReturns = permissionsV2View

        val mvcResult =
            mockMvc
                .perform(
                    get("${PermissionsV2Controller.ENDPOINT}/{uuid}", uuid.toString())
                        .credHubAuthHeader()
                        .contentType(MediaType.APPLICATION_JSON),
                ).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        pathParameters(
                            parameterWithName("uuid")
                                .description("The permission uuid"),
                        ),
                    ),
                ).andReturn()

        assertThat(spyPermissionsV2Handler.permissionsCalledwithGuid).isEqualTo(uuid.toString())
        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody =
            """
            {
              "path": "/some-path/*",
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
    fun postPermissions__adds_a_leading_slash() {
        val permissionsV2View =
            PermissionsV2View(
                "some-path/*",
                listOf(READ, WRITE),
                "some-actor",
                uuid,
            )

        val expectedPermissionsV2Request =
            PermissionsV2Request(
                "/some-path/*",
                "some-actor",
                mutableListOf(READ, WRITE),
            )

        spyPermissionsV2Handler.writev2permissionsReturns = permissionsV2View

        val mvcResult =
            mockMvc
                .perform(
                    post(PermissionsV2Controller.ENDPOINT)
                        .credHubAuthHeader()
                        .contentType(MediaType.APPLICATION_JSON)
                        // language=json
                        .content(
                            """
                            {
                              "path": "some-path/*",
                              "actor": "some-actor",
                              "operations": [
                                "read",
                                "write"
                              ]
                            }
                            """.trimIndent(),
                        ),
                ).andExpect(status().isCreated())
                .andReturn()

        val actualPermissionsV2Request = spyPermissionsV2Handler.writev2permissionsCalledwithPermissionrequest
        assertThat(actualPermissionsV2Request.actor).isEqualTo(expectedPermissionsV2Request.actor)
        assertThat(actualPermissionsV2Request.getPath()).isEqualTo(expectedPermissionsV2Request.getPath())

        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody =
            """
            {
              "path": "some-path/*",
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
    fun deletePermissions_v2_by_uuid__returns_a_permission() {
        val permissionsV2View =
            PermissionsV2View(
                "/some-path/*",
                listOf(READ, WRITE),
                "some-actor",
                uuid,
            )
        spyPermissionsV2Handler.deletepermissionsReturns = permissionsV2View

        val mvcResult =
            mockMvc
                .perform(
                    delete("${PermissionsV2Controller.ENDPOINT}/{uuid}", uuid.toString())
                        .credHubAuthHeader()
                        .contentType(MediaType.APPLICATION_JSON),
                ).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        pathParameters(
                            parameterWithName("uuid")
                                .description("The permission uuid"),
                        ),
                    ),
                ).andReturn()

        assertThat(spyPermissionsV2Handler.deletepermissionsCalledwithGuid).isEqualTo(uuid.toString())
        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody =
            """
            {
              "path": "/some-path/*",
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
    fun putPermissions_v2__returns_a_permission() {
        val permissionsV2View =
            PermissionsV2View(
                "/some-path/*",
                listOf(READ, WRITE),
                "some-actor",
                uuid,
            )
        spyPermissionsV2Handler.putpermissionsReturns = permissionsV2View

        val mvcResult =
            mockMvc
                .perform(
                    put("${PermissionsV2Controller.ENDPOINT}/{uuid}", uuid.toString())
                        .credHubAuthHeader()
                        .contentType(MediaType.APPLICATION_JSON)
                        // language=json
                        .content(
                            """
                            {
                              "path": "/some-path/*",
                              "actor": "some-actor",
                              "operations": [
                                "read",
                                "write"
                              ]
                            }
                            """.trimIndent(),
                        ),
                ).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        pathParameters(
                            parameterWithName("uuid")
                                .description("The permission uuid"),
                        ),
                        requestFields(
                            fieldWithPath("path")
                                .description(
                                    "The credential path. Can be either a path with an asterisk (*) at the end, or the full name of a credential.",
                                ),
                            fieldWithPath("actor")
                                .description("The credential actor"),
                            getPermissionOperationsRequestField(),
                        ),
                    ),
                ).andReturn()

        assertThat(spyPermissionsV2Handler.putpermissionsCalledwithGuid).isEqualTo(uuid.toString())
        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody =
            """
            {
              "path": "/some-path/*",
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
    fun patchPermissions_v2__returns_a_permission() {
        val permissionsV2View =
            PermissionsV2View(
                "/some-path/*",
                listOf(READ, WRITE),
                "some-actor",
                uuid,
            )

        spyPermissionsV2Handler.patchpermissionsReturns = permissionsV2View

        val mvcResult =
            mockMvc
                .perform(
                    patch("${PermissionsV2Controller.ENDPOINT}/{uuid}", uuid.toString())
                        .credHubAuthHeader()
                        .contentType(MediaType.APPLICATION_JSON)
                        // language=json
                        .content(
                            """
                            {
                              "operations": [
                                "read",
                                "write"
                              ]
                            }
                            """.trimIndent(),
                        ),
                ).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        pathParameters(
                            parameterWithName("uuid")
                                .description("The permission uuid"),
                        ),
                        requestFields(
                            getPermissionOperationsRequestField(),
                        ),
                    ),
                ).andReturn()

        assertThat(spyPermissionsV2Handler.patchpermissionsCalledwithGuid).isEqualTo(uuid.toString())
        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody =
            """
            {
              "path": "/some-path/*",
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
    fun postPermissions_v2__returns_a_permission() {
        val permissionsV2View =
            PermissionsV2View(
                "/some-path/*",
                listOf(READ, WRITE),
                "some-actor",
                uuid,
            )

        spyPermissionsV2Handler.writev2permissionsReturns = permissionsV2View

        val mvcResult =
            mockMvc
                .perform(
                    post(PermissionsV2Controller.ENDPOINT)
                        .credHubAuthHeader()
                        .contentType(MediaType.APPLICATION_JSON)
                        // language=json
                        .content(
                            """
                            {
                              "path": "/some-path/*",
                              "actor": "some-actor",
                              "operations": [
                                "read",
                                "write"
                              ]
                            }
                            """.trimIndent(),
                        ),
                ).andExpect(status().isCreated())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andDo(
                    document(
                        CredHubRestDocs.DOCUMENT_IDENTIFIER,
                        requestFields(
                            fieldWithPath("path")
                                .description(
                                    "The credential path. Can be either a path with an asterisk (*) at the end, or the full name of a credential.",
                                ),
                            fieldWithPath("actor")
                                .description("The credential actor"),
                            getPermissionOperationsRequestField(),
                        ),
                    ),
                ).andReturn()

        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody =
            """
            {
              "path": "/some-path/*",
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

    private fun getPermissionOperationsRequestField(): FieldDescriptor =
        fieldWithPath("operations")
            .description(
                """
                        The list of permissions to be granted.
                        Supported operations are: ${
                    PermissionOperation.values().joinToString(
                        transform = { x ->
                            x.operation.lowercase()
                        },
                        separator = ", ",
                    )
                }
                """.trimIndent(),
            )
}

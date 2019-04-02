package org.cloudfoundry.credhub.controllers.v1.permissions

import org.assertj.core.api.Assertions.assertThat
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.helpers.CredHubRestDocs
import org.cloudfoundry.credhub.helpers.MockMvcFactory
import org.cloudfoundry.credhub.helpers.credHubAuthHeader
import org.cloudfoundry.credhub.permissions.PermissionsV1Controller
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsRequest
import org.cloudfoundry.credhub.views.PermissionsView
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.skyscreamer.jsonassert.JSONAssert
import org.springframework.http.MediaType
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get
import org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post
import org.springframework.restdocs.payload.FieldDescriptor
import org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath
import org.springframework.restdocs.payload.PayloadDocumentation.requestFields
import org.springframework.restdocs.request.RequestDocumentation.parameterWithName
import org.springframework.restdocs.request.RequestDocumentation.requestParameters
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.util.UUID

class PermissionsV1ControllerTest {
    @Rule
    @JvmField
    val restDocumentation = JUnitRestDocumentation()

    val uuid = UUID.randomUUID()

    lateinit var mockMvc: MockMvc
    lateinit var spyPermissionsV1Handler: SpyPermissionsV1Handler

    @Before
    fun setUp() {
        spyPermissionsV1Handler = SpyPermissionsV1Handler()
        val permissionsV1Controller = PermissionsV1Controller(spyPermissionsV1Handler, CEFAuditRecord())

        mockMvc = MockMvcFactory.newSpringRestDocMockMvc(permissionsV1Controller, restDocumentation)
    }

    @Test
    fun GET__permissions_v1__returns_permissions() {
        spyPermissionsV1Handler.getPermissions__returns_permissionsView = PermissionsView(
            "/some-credential-name",
            listOf(
                PermissionEntry(
                    "some-actor",
                    "some-path",
                    listOf(
                        PermissionOperation.READ
                    )
                )
            )
        )

        val mvcResult = mockMvc
            .perform(
                get(PermissionsV1Controller.ENDPOINT)
                    .credHubAuthHeader()
                    .param("credential_name", "some-credential-name")
            )
            .andExpect(status().isOk)
            .andExpect(MockMvcResultMatchers.content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters(
                        parameterWithName("credential_name")
                            .description("The name of the credential to get permissions for.")
                    )
                )
            )
            .andReturn()

        assertThat(spyPermissionsV1Handler.getPermissions__calledWith_name).isEqualTo("/some-credential-name")

        val actualResponseBody = mvcResult.response.contentAsString

        // language=json
        val expectedResponseBody = """
            {
              "credential_name": "/some-credential-name",
              "permissions": [
                {
                  "actor": "some-actor",
                  "path": "some-path",
                  "operations": [
                    "read"
                  ]
                }
              ]
            }
        """.trimIndent()

        JSONAssert.assertEquals(expectedResponseBody, actualResponseBody, true)
    }

    @Test
    fun POST__permissions_v1__returns_201() {
        // language=json
        val requestBody = """
            {
              "credential_name": "/some-credential-name",
              "permissions": [
                {
                  "actor": "some-actor",
                  "path": "some-path",
                  "operations": [
                    "read"
                  ]
                }
              ]
            }
        """.trimIndent()

        mockMvc
            .perform(
                post(PermissionsV1Controller.ENDPOINT)
                    .credHubAuthHeader()
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(requestBody)
            )
            .andExpect(status().isCreated)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestFields(
                        fieldWithPath("credential_name")
                            .description("The name of the credential to create permissions for"),
                        fieldWithPath("permissions[].path")
                            .description("The credential path"),
                        fieldWithPath("permissions[].actor")
                            .description("The credential actor"),
                        getPermissionOperationsRequestField()
                    )
                )
            )
            .andReturn()

        val expectedPermissionsRequest = PermissionsRequest(
            "/some-credential-name",
            listOf(
                PermissionEntry(
                    "some-actor",
                    "some-path",
                    listOf(
                        PermissionOperation.READ
                    )
                )
            )

        )
        assertThat(spyPermissionsV1Handler.writePermissions__calledWith_request)
            .isEqualTo(expectedPermissionsRequest)
    }

    @Test
    fun DELETE__permission_v1__returns_204() {
        mockMvc
            .perform(
                delete(PermissionsV1Controller.ENDPOINT)
                    .credHubAuthHeader()
                    .param("credential_name", "some-credential-name")
                    .param("actor", "some-actor")
            )
            .andExpect(status().isNoContent)
            .andDo(
                document(
                    CredHubRestDocs.DOCUMENT_IDENTIFIER,
                    requestParameters(
                        parameterWithName("credential_name")
                            .description("The name of the credential to delete permissions for."),
                        parameterWithName("actor")
                            .description("The actor to delete permissions for.")
                    )
                )
            )

        assertThat(spyPermissionsV1Handler.deletePermissionEntry__calledWith_credentialName).isEqualTo("/some-credential-name")
        assertThat(spyPermissionsV1Handler.deletePermissionEntry__calledWith_actor).isEqualTo("some-actor")
    }

    private fun getPermissionOperationsRequestField(): FieldDescriptor {
        return fieldWithPath("permissions[].operations")
            .description(
                """
                    The list of permissions to be granted.
                    Supported operations are: ${
                        PermissionOperation.values().joinToString(
                            transform = {
                                x -> x.operation.toLowerCase()
                            },
                            separator = ", "
                        )
                    }
                """.trimIndent()
            )
    }
}

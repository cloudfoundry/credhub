package org.cloudfoundry.credhub.handlers

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.data.PermissionData
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.domain.ValueCredentialVersion
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.permissions.DefaultPermissionsV1Handler
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsRequest
import org.cloudfoundry.credhub.views.PermissionsView
import org.junit.Before
import org.junit.Test

class DefaultPermissionsV1HandlerTest {
    private lateinit var credentialVersion: CredentialVersion
    private lateinit var subject: DefaultPermissionsV1Handler
    private lateinit var spyPermissionService: SpyPermissionService
    private lateinit var spyPermissionedCredentialService: SpyCredentialService

    companion object {
        private const val CREDENTIAL_NAME = "/test-credential"
        private const val ACTOR_NAME = "test-actor"
        private const val OTHER_ACTOR_NAME = "other-test-actor"
    }

    @Before
    fun beforeEach() {
        credentialVersion =
            ValueCredentialVersion(
                ValueCredentialVersionData(CREDENTIAL_NAME),
            )

        spyPermissionService = SpyPermissionService()
        spyPermissionedCredentialService = SpyCredentialService()
        subject =
            DefaultPermissionsV1Handler(
                spyPermissionService,
                spyPermissionedCredentialService,
            )
    }

    @Test
    fun `getPermissions returns a permissionsView`() {
        spyPermissionedCredentialService.findmostrecentReturnsCredentialversion = credentialVersion
        spyPermissionService.permissionsReturnsPermissionentries = listOf(PermissionEntry())

        val actual = subject.getPermissions(CREDENTIAL_NAME)
        val expected =
            PermissionsView(
                CREDENTIAL_NAME,
                listOf(PermissionEntry()),
            )

        assertThat(actual).isEqualTo(expected)
        assertThat(spyPermissionedCredentialService.findmostrecentCalledwithCredentialname).isEqualTo(CREDENTIAL_NAME)
        assertThat(spyPermissionService.permissionsCalledwithCredentialversion).isEqualTo(credentialVersion)
    }

    @Test
    fun `writePermissions returns void`() {
        val permissionsRequest =
            PermissionsRequest(
                CREDENTIAL_NAME,
                mutableListOf(
                    PermissionEntry(ACTOR_NAME, "", mutableListOf(PermissionOperation.DELETE)),
                    PermissionEntry(OTHER_ACTOR_NAME, "", mutableListOf(PermissionOperation.READ)),
                ),
            )

        val expected =
            PermissionsRequest(
                CREDENTIAL_NAME,
                mutableListOf(
                    PermissionEntry(ACTOR_NAME, CREDENTIAL_NAME, mutableListOf(PermissionOperation.DELETE)),
                    PermissionEntry(OTHER_ACTOR_NAME, CREDENTIAL_NAME, mutableListOf(PermissionOperation.READ)),
                ),
            )
        spyPermissionService.savepermissionsforuserReturnsPermissiondatalist = emptyList<PermissionData>().toMutableList()

        subject.writePermissions(permissionsRequest)

        assertThat(spyPermissionService.savepermissionsforuserCalledwithPermissionentrylist)
            .isEqualTo(expected.permissions)
    }

    @Test
    fun `deletePermissionEntry returns void for successful delete`() {
        spyPermissionService.deletepermissionsReturns = true

        subject.deletePermissionEntry(CREDENTIAL_NAME, ACTOR_NAME)

        assertThat(spyPermissionService.deletepermissionsCalledwithCredentialname).isEqualTo(CREDENTIAL_NAME)
        assertThat(spyPermissionService.deletepermissionsCalledwithActor).isEqualTo(ACTOR_NAME)
    }

    @Test
    fun `deletePermissionEntry throws exception for delete failure`() {
        spyPermissionService.deletepermissionsReturns = false

        assertThatThrownBy {
            subject.deletePermissionEntry(CREDENTIAL_NAME, ACTOR_NAME)
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Credential.INVALID_ACCESS)

        assertThat(spyPermissionService.deletepermissionsCalledwithCredentialname).isEqualTo(CREDENTIAL_NAME)
        assertThat(spyPermissionService.deletepermissionsCalledwithActor).isEqualTo(ACTOR_NAME)
    }
}

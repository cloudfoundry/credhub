package org.cloudfoundry.credhub.handlers

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.PermissionOperation.DELETE
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.data.PermissionData
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.domain.ValueCredentialVersion
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.permissions.DefaultPermissionsV2Handler
import org.cloudfoundry.credhub.permissions.DefaultPermissionsV2Handler.Companion.INVALID_NUMBER_OF_PERMISSIONS
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.views.PermissionsV2View
import org.junit.Before
import org.junit.Test
import java.util.UUID

class DefaultPermissionsV2HandlerTest {
    private lateinit var credentialVersion: CredentialVersion
    private lateinit var subject: DefaultPermissionsV2Handler

    private lateinit var spyPermissionService: SpyPermissionService

    companion object {
        private const val CREDENTIAL_NAME = "/test-credential"
        private const val ACTOR_NAME = "test-actor"
    }

    @Before
    fun beforeEach() {
        credentialVersion =
            ValueCredentialVersion(
                ValueCredentialVersionData(CREDENTIAL_NAME),
            )

        spyPermissionService = SpyPermissionService()
        subject = DefaultPermissionsV2Handler(spyPermissionService)
    }

    @Test
    fun `writePermissions returns PermissionsV2View when successful`() {
        val permissionsRequest =
            PermissionsV2Request(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE),
            )

        spyPermissionService.savepermissionsforuserReturnsPermissiondatalist =
            mutableListOf(
                PermissionData(
                    CREDENTIAL_NAME,
                    ACTOR_NAME,
                    mutableListOf(PermissionOperation.DELETE),
                ),
            )

        subject.writePermissions(permissionsRequest)

        assertThat(spyPermissionService.savepermissionsforuserCalledwithPermissionentrylist)
            .isEqualTo(
                mutableListOf(
                    PermissionEntry(
                        ACTOR_NAME,
                        CREDENTIAL_NAME,
                        mutableListOf(PermissionOperation.DELETE),
                    ),
                ),
            )
    }

    @Test
    fun `writePermissions throws exception for too many permissions`() {
        val permissionsRequest =
            PermissionsV2Request(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE),
            )

        spyPermissionService.savepermissionsforuserReturnsPermissiondatalist = emptyList<PermissionData>().toMutableList()

        assertThatThrownBy {
            subject.writePermissions(permissionsRequest)
        }.isInstanceOf(IllegalArgumentException::class.java)
            .hasMessage(INVALID_NUMBER_OF_PERMISSIONS)

        assertThat(spyPermissionService.savepermissionsforuserCalledwithPermissionentrylist)
            .isEqualTo(
                mutableListOf(
                    PermissionEntry(
                        ACTOR_NAME,
                        CREDENTIAL_NAME,
                        mutableListOf(PermissionOperation.DELETE),
                    ),
                ),
            )
    }

    @Test
    fun `getPermissions returns PermissionsV2View`() {
        val uuid = UUID.randomUUID()

        spyPermissionService.permissionsReturnsPermissiondata =
            PermissionData(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(
                    PermissionOperation.READ,
                ),
            )

        val actual = subject.getPermissions(uuid.toString())

        val expected =
            PermissionsV2View(
                CREDENTIAL_NAME,
                mutableListOf(
                    READ,
                ),
                ACTOR_NAME,
                uuid,
            )

        assertThat(spyPermissionService.permissionsCalledwithUuid).isEqualTo(uuid)
        assertThat(actual).isEqualTo(expected)
    }

    @Test
    fun `getPermissions withInvalidUUID throwsNotFound`() {
        assertThatThrownBy {
            subject.getPermissions("Invalid-UUID")
        }.hasMessage(ErrorMessages.Permissions.INVALID_ACCESS)
    }

    @Test
    fun `putPermissions returns PermissionsV2View`() {
        val uuid = UUID.randomUUID()

        val permissionsRequest =
            PermissionsV2Request(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE),
            )

        spyPermissionService.putpermissionsReturnsPermissiondata =
            PermissionData(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE),
            )

        val actual = subject.putPermissions(uuid.toString(), permissionsRequest)

        val expected =
            PermissionsV2View(
                CREDENTIAL_NAME,
                mutableListOf(
                    DELETE,
                ),
                ACTOR_NAME,
                null,
            )

        assertThat(spyPermissionService.putpermissionsCalledwithGuid).isEqualTo(uuid.toString())
        assertThat(spyPermissionService.putpermissionsCalledwithPermissionsrequest).isEqualTo(permissionsRequest)
        assertThat(actual).isEqualTo(expected)
    }

    @Test
    fun `patchPermissions returns PermissionsV2View`() {
        val uuid = UUID.randomUUID()
        val operations = mutableListOf(PermissionOperation.READ)

        spyPermissionService.patchpermissionsReturnsPermissiondata =
            PermissionData(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(
                    PermissionOperation.READ,
                ),
            )

        val actual = subject.patchPermissions(uuid.toString(), operations)
        val expected =
            PermissionsV2View(
                CREDENTIAL_NAME,
                mutableListOf(
                    READ,
                ),
                ACTOR_NAME,
                null,
            )

        assertThat(actual).isEqualTo(expected)
        assertThat(spyPermissionService.patchpermissionsCalledwithGuid).isEqualTo(uuid.toString())
        assertThat(spyPermissionService.patchpermissionsCalledwithOperations).isEqualTo(operations)
    }

    @Test
    fun `writeV2Permissions returns PermissionsV2View`() {
        val permissionsRequest =
            PermissionsV2Request(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE),
            )

        spyPermissionService.savev2permissionsReturnsPermissiondata =
            PermissionData(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE),
            )

        val actual = subject.writeV2Permissions(permissionsRequest)

        val expected =
            PermissionsV2View(
                CREDENTIAL_NAME,
                mutableListOf(
                    DELETE,
                ),
                ACTOR_NAME,
                null,
            )

        assertThat(spyPermissionService.savev2permissionsCalledwithPermissionsrequest)
            .isEqualTo(permissionsRequest)
        assertThat(actual).isEqualTo(expected)
    }

    @Test
    fun `deletePermissions returns PermissionsV2View`() {
        val uuid = UUID.randomUUID()

        spyPermissionService.deletepermissionsReturnsPermissiondata =
            PermissionData(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE),
            )

        val actual = subject.deletePermissions(uuid.toString())
        val expected =
            PermissionsV2View(
                CREDENTIAL_NAME,
                mutableListOf(
                    DELETE,
                ),
                ACTOR_NAME,
                null,
            )

        assertThat(actual).isEqualTo(expected)
        assertThat(spyPermissionService.deletepermissionsCalledwithGuid).isEqualTo(uuid.toString())
    }

    @Test
    fun `findByPathAndActor returns PermissionsV2View`() {
        spyPermissionService.findbypathandactorReturnsPermissiondata =
            PermissionData(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE),
            )

        val actual = subject.findByPathAndActor(CREDENTIAL_NAME, ACTOR_NAME)
        val expected =
            PermissionsV2View(
                CREDENTIAL_NAME,
                mutableListOf(
                    DELETE,
                ),
                ACTOR_NAME,
                null,
            )

        assertThat(spyPermissionService.findbypathandactorCalledwithPath).isEqualTo(CREDENTIAL_NAME)
        assertThat(spyPermissionService.findbypathandactorCalledwithActor).isEqualTo(ACTOR_NAME)
        assertThat(actual).isEqualTo(expected)
    }

    @Test
    fun `findByPathAndActor throws exception when path and actor combination does not exist`() {
        spyPermissionService.findbypathandactorReturnsPermissiondata = null

        assertThatThrownBy {
            subject.findByPathAndActor(CREDENTIAL_NAME, ACTOR_NAME)
        }.isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Permissions.INVALID_ACCESS)

        assertThat(spyPermissionService.findbypathandactorCalledwithPath).isEqualTo(CREDENTIAL_NAME)
        assertThat(spyPermissionService.findbypathandactorCalledwithActor).isEqualTo(ACTOR_NAME)
    }
}

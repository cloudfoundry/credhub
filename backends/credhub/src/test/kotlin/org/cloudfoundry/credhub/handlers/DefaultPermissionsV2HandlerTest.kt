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
        credentialVersion = ValueCredentialVersion(
            ValueCredentialVersionData(CREDENTIAL_NAME)
        )

        spyPermissionService = SpyPermissionService()
        subject = DefaultPermissionsV2Handler(spyPermissionService)
    }

    @Test
    fun `writePermissions returns PermissionsV2View when successful`() {
        val permissionsRequest = PermissionsV2Request(
            CREDENTIAL_NAME,
            ACTOR_NAME,
            mutableListOf(PermissionOperation.DELETE)
        )

        spyPermissionService.savePermissionsForUser__returns_permissionDataList =
            listOf(PermissionData(CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE)
            ))

        subject.writePermissions(permissionsRequest)

        assertThat(spyPermissionService.savePermissionsForUser__calledWith_permissionEntryList)
            .isEqualTo(mutableListOf(
                PermissionEntry(
                    ACTOR_NAME,
                    CREDENTIAL_NAME,
                    mutableListOf(PermissionOperation.DELETE)
                )
            ))
    }

    @Test
    fun `writePermissions throws exception for too many permissions`() {
        val permissionsRequest = PermissionsV2Request(
            CREDENTIAL_NAME,
            ACTOR_NAME,
            mutableListOf(PermissionOperation.DELETE)
        )

        spyPermissionService.savePermissionsForUser__returns_permissionDataList = emptyList()

        assertThatThrownBy {
            subject.writePermissions(permissionsRequest)
        }
            .isInstanceOf(IllegalArgumentException::class.java)
            .hasMessage(INVALID_NUMBER_OF_PERMISSIONS)

        assertThat(spyPermissionService.savePermissionsForUser__calledWith_permissionEntryList)
            .isEqualTo(mutableListOf(
                PermissionEntry(
                    ACTOR_NAME,
                    CREDENTIAL_NAME,
                    mutableListOf(PermissionOperation.DELETE)
                )
            ))
    }

    @Test
    fun `getPermissions returns PermissionsV2View`() {
        val uuid = UUID.randomUUID()

        spyPermissionService.getPermissions__returns_permissionData = PermissionData(
            CREDENTIAL_NAME,
            ACTOR_NAME,
            mutableListOf(
                PermissionOperation.READ
            )
        )

        val actual = subject.getPermissions(uuid)

        val expected = PermissionsV2View(
            CREDENTIAL_NAME,
            mutableListOf(
                PermissionOperation.READ
            ),
            ACTOR_NAME,
            uuid
        )

        assertThat(spyPermissionService.getPermissions__calledWith_uuid).isEqualTo(uuid)
        assertThat(actual).isEqualTo(expected)
    }

    @Test
    fun `putPermissions returns PermissionsV2View`() {
        val uuid = UUID.randomUUID()

        val permissionsRequest = PermissionsV2Request(
            CREDENTIAL_NAME,
            ACTOR_NAME,
            mutableListOf(PermissionOperation.DELETE)
        )

        spyPermissionService.putPermissions__returns_permissionData =
            PermissionData(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE)
            )

        val actual = subject.putPermissions(uuid.toString(), permissionsRequest)

        val expected = PermissionsV2View(
            CREDENTIAL_NAME,
            mutableListOf(
                PermissionOperation.DELETE
            ),
            ACTOR_NAME,
            null
        )

        assertThat(spyPermissionService.putPermissions__calledWith_guid).isEqualTo(uuid.toString())
        assertThat(spyPermissionService.putPermissions__calledWith_permissionsRequest).isEqualTo(permissionsRequest)
        assertThat(actual).isEqualTo(expected)
    }

    @Test
    fun `patchPermissions returns PermissionsV2View`() {
        val uuid = UUID.randomUUID()
        val operations = listOf(PermissionOperation.READ)

        spyPermissionService.patchPermissions__returns_permissionData = PermissionData(
            CREDENTIAL_NAME,
            ACTOR_NAME,
            mutableListOf(
                PermissionOperation.READ
            )
        )

        val actual = subject.patchPermissions(uuid.toString(), operations)
        val expected = PermissionsV2View(
            CREDENTIAL_NAME,
            mutableListOf(
                PermissionOperation.READ
            ),
            ACTOR_NAME,
            null
        )

        assertThat(actual).isEqualTo(expected)
        assertThat(spyPermissionService.patchPermissions__calledWith_guid).isEqualTo(uuid.toString())
        assertThat(spyPermissionService.patchPermissions__calledWith_operations).isEqualTo(operations)
    }

    @Test
    fun `writeV2Permissions returns PermissionsV2View`() {
        val permissionsRequest = PermissionsV2Request(
            CREDENTIAL_NAME,
            ACTOR_NAME,
            mutableListOf(PermissionOperation.DELETE)
        )

        spyPermissionService.saveV2Permissions__returns_permissionData =
            PermissionData(
                CREDENTIAL_NAME,
                ACTOR_NAME,
                mutableListOf(PermissionOperation.DELETE)
            )

        val actual = subject.writeV2Permissions(permissionsRequest)

        val expected = PermissionsV2View(
            CREDENTIAL_NAME,
            mutableListOf(
                PermissionOperation.DELETE
            ),
            ACTOR_NAME,
            null
        )

        assertThat(spyPermissionService.saveV2Permissions__calledWith_permissionsRequest)
            .isEqualTo(permissionsRequest)
        assertThat(actual).isEqualTo(expected)
    }

    @Test
    fun `deletePermissions returns PermissionsV2View`() {
        val uuid = UUID.randomUUID()

        spyPermissionService.deletePermissions__returns_permissionData = PermissionData(
            CREDENTIAL_NAME,
            ACTOR_NAME,
            mutableListOf(PermissionOperation.DELETE)
        )

        val actual = subject.deletePermissions(uuid.toString())
        val expected = PermissionsV2View(
            CREDENTIAL_NAME,
            mutableListOf(
                PermissionOperation.DELETE
            ),
            ACTOR_NAME,
            null
        )

        assertThat(actual).isEqualTo(expected)
        assertThat(spyPermissionService.deletePermissions__calledWith_guid).isEqualTo(uuid.toString())
    }

    @Test
    fun `findByPathAndActor returns PermissionsV2View`() {
        spyPermissionService.findByPathAndActor__returns_permissionData = PermissionData(
            CREDENTIAL_NAME,
            ACTOR_NAME,
            mutableListOf(PermissionOperation.DELETE)
        )

        val actual = subject.findByPathAndActor(CREDENTIAL_NAME, ACTOR_NAME)
        val expected = PermissionsV2View(
            CREDENTIAL_NAME,
            mutableListOf(
                PermissionOperation.DELETE
            ),
            ACTOR_NAME,
            null
        )

        assertThat(spyPermissionService.findByPathAndActor__calledWith_path).isEqualTo(CREDENTIAL_NAME)
        assertThat(spyPermissionService.findByPathAndActor__calledWith_actor).isEqualTo(ACTOR_NAME)
        assertThat(actual).isEqualTo(expected)
    }

    @Test
    fun `findByPathAndActor throws exception when path and actor combination does not exist`() {
        spyPermissionService.findByPathAndActor__returns_permissionData = null

        assertThatThrownBy {
            subject.findByPathAndActor(CREDENTIAL_NAME, ACTOR_NAME)
        }
            .isInstanceOf(EntryNotFoundException::class.java)
            .hasMessage(ErrorMessages.Permissions.INVALID_ACCESS)

        assertThat(spyPermissionService.findByPathAndActor__calledWith_path).isEqualTo(CREDENTIAL_NAME)
        assertThat(spyPermissionService.findByPathAndActor__calledWith_actor).isEqualTo(ACTOR_NAME)
    }
}

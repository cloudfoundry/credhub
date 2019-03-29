package org.cloudfoundry.credhub.handlers

import com.google.common.collect.Lists
import com.google.common.collect.Lists.newArrayList
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.data.CredentialDataService
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsRequest
import org.cloudfoundry.credhub.services.DefaultPermissionedCredentialService
import org.cloudfoundry.credhub.services.PermissionCheckingService
import org.cloudfoundry.credhub.services.PermissionService
import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.Matchers.contains
import org.hamcrest.Matchers.hasSize
import org.junit.Assert.assertThat
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import org.mockito.Mockito.times
import org.mockito.Mockito.verify
import java.util.Arrays

@RunWith(JUnit4::class)
class DefaultPermissionsV1HandlerTest {
    private val credential = Credential(CREDENTIAL_NAME)
    private val credentialVersion = PasswordCredentialVersion(PasswordCredentialVersionData(CREDENTIAL_NAME))
    private lateinit var subject: DefaultPermissionsV1Handler
    private lateinit var permissionService: PermissionService
    private lateinit var permissionCheckingService: PermissionCheckingService
    private lateinit var credentialDataService: CredentialDataService
    private lateinit var permissionedCredentialService: DefaultPermissionedCredentialService
    private lateinit var permissionsRequest: PermissionsRequest

    @Before
    fun beforeEach() {
        permissionService = mock<PermissionService>(PermissionService::class.java)
        permissionCheckingService = mock<PermissionCheckingService>(PermissionCheckingService::class.java)
        credentialDataService = mock<CredentialDataService>(CredentialDataService::class.java)
        permissionedCredentialService = mock<DefaultPermissionedCredentialService>(DefaultPermissionedCredentialService::class.java)
        subject = DefaultPermissionsV1Handler(
            permissionService,
            permissionedCredentialService
        )

        permissionsRequest = mock<PermissionsRequest>(PermissionsRequest::class.java)

        `when`<CredentialVersion>(permissionedCredentialService.findMostRecent(CREDENTIAL_NAME)).thenReturn(credentialVersion)
        `when`<Credential>(credentialDataService.find(any<String>(String::class.java))).thenReturn(credential)
    }

    @Test
    fun getPermissions_whenTheNameDoesntStartWithASlash_fixesTheName() {
        val accessControlList = newArrayList<PermissionEntry>()
        `when`<List<PermissionEntry>>(permissionService.getPermissions(any<CredentialVersion>(CredentialVersion::class.java)))
            .thenReturn(accessControlList)

        val response = subject.getPermissions(CREDENTIAL_NAME)
        assertThat<String>(response.credentialName, equalTo<String>(CREDENTIAL_NAME))

    }

    @Test
    fun getPermissions_verifiesTheUserHasPermissionToReadTheAcl_andReturnsTheAclResponse() {
        val operations = newArrayList<PermissionOperation>(
            PermissionOperation.READ,
            PermissionOperation.WRITE
        )

        val permissionEntry = PermissionEntry(
            ACTOR_NAME,
            "test-path",
            operations
        )
        val accessControlList = newArrayList<PermissionEntry>(permissionEntry)
        `when`<List<PermissionEntry>>(permissionService.getPermissions(credentialVersion))
            .thenReturn(accessControlList)

        val response = subject.getPermissions(
            CREDENTIAL_NAME
        )

        val accessControlEntries = response.permissions

        assertThat<String>(response.credentialName, equalTo<String>(CREDENTIAL_NAME))
        assertThat<List<PermissionEntry>>(accessControlEntries, hasSize<PermissionEntry>(1))

        val entry = accessControlEntries[0]

        assertThat<String>(entry.actor, equalTo<String>(ACTOR_NAME))

        val allowedOperations = entry.allowedOperations
        assertThat<List<PermissionOperation>>(allowedOperations, contains<PermissionOperation>(
            equalTo<PermissionOperation>(PermissionOperation.READ),
            equalTo<PermissionOperation>(PermissionOperation.WRITE)
        ))
    }

    @Test
    fun setPermissions_setsAndReturnsThePermissions() {
        `when`<Boolean>(permissionCheckingService
            .userAllowedToOperateOnActor(ACTOR_NAME))
            .thenReturn(true)

        val operations = newArrayList<PermissionOperation>(
            PermissionOperation.READ,
            PermissionOperation.WRITE
        )
        val permissionEntry = PermissionEntry(ACTOR_NAME, "test-path", operations)
        val accessControlList = newArrayList<PermissionEntry>(permissionEntry)

        val preexistingPermissionEntry = PermissionEntry(ACTOR_NAME2, "test-path", Lists.newArrayList(PermissionOperation.READ)
        )
        val expectedControlList = newArrayList<PermissionEntry>(permissionEntry,
            preexistingPermissionEntry)

        `when`<List<PermissionEntry>>(permissionService.getPermissions(credentialVersion))
            .thenReturn(expectedControlList)

        `when`<String>(permissionsRequest.credentialName).thenReturn(CREDENTIAL_NAME)
        `when`<List<PermissionEntry>>(permissionsRequest.permissions).thenReturn(accessControlList)

        subject.writePermissions(permissionsRequest)

        val permissionsListCaptor = ArgumentCaptor.forClass(List::class.java)

        verify<PermissionService>(permissionService).savePermissionsForUser(permissionsListCaptor.capture() as? List<PermissionEntry>)

        val entry = accessControlList.get(0)
        assertThat<String>(entry.actor, equalTo<String>(ACTOR_NAME))
        assertThat<String>(entry.path, equalTo<String>(CREDENTIAL_NAME))
        assertThat<List<PermissionOperation>>(entry.allowedOperations, contains<PermissionOperation>(equalTo<PermissionOperation>(PermissionOperation.READ), equalTo<PermissionOperation>(PermissionOperation.WRITE)))
    }

    @Test
    fun setPermissions_whenUserUpdatesOwnPermission_throwsException() {
        `when`<Boolean>(permissionCheckingService
            .userAllowedToOperateOnActor(ACTOR_NAME))
            .thenReturn(false)

        val accessControlList = Arrays.asList(PermissionEntry(ACTOR_NAME, "test-path", Arrays.asList(
            PermissionOperation.READ)))
        `when`<String>(permissionsRequest.credentialName).thenReturn(CREDENTIAL_NAME)
        `when`<List<PermissionEntry>>(permissionsRequest.permissions).thenReturn(accessControlList)

        try {
            subject.writePermissions(permissionsRequest)
        } catch (e: InvalidPermissionOperationException) {
            assertThat<String>(e.message, equalTo<String>(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION))
            verify<PermissionService>(permissionService, times(0)).savePermissionsForUser(any<List<PermissionEntry>>())
        }

    }

    @Test
    fun deletePermissions_whenTheUserHasPermission_deletesTheAce() {
        `when`<Boolean>(permissionService.deletePermissions(CREDENTIAL_NAME, ACTOR_NAME))
            .thenReturn(true)
        `when`<Boolean>(permissionCheckingService
            .userAllowedToOperateOnActor(ACTOR_NAME))
            .thenReturn(true)

        subject.deletePermissionEntry(CREDENTIAL_NAME, ACTOR_NAME
        )

        verify<PermissionService>(permissionService, times(1)).deletePermissions(
            CREDENTIAL_NAME, ACTOR_NAME)

    }

    @Test
    fun deletePermissions_whenNothingIsDeleted_throwsAnException() {
        `when`<Boolean>(permissionService.deletePermissions(CREDENTIAL_NAME, ACTOR_NAME))
            .thenReturn(false)

        try {
            subject.deletePermissionEntry(CREDENTIAL_NAME, ACTOR_NAME
            )
            fail("should throw")
        } catch (e: EntryNotFoundException) {
            assertThat<String>(e.message, equalTo<String>(ErrorMessages.Credential.INVALID_ACCESS))
        }

    }

    companion object {
        private val CREDENTIAL_NAME = "/test-credential"
        private val ACTOR_NAME = "test-actor"
        private val ACTOR_NAME2 = "someone-else"
        private val USER = "test-user"
    }
}

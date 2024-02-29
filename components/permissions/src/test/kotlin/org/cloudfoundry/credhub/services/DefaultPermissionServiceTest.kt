package org.cloudfoundry.credhub.services

import com.google.common.collect.Lists
import com.google.common.collect.Lists.newArrayList
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.auth.UserContext
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.data.PermissionData
import org.cloudfoundry.credhub.data.PermissionDataService
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion
import org.cloudfoundry.credhub.entities.Credential
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.hamcrest.core.IsEqual
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyString
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import java.util.Arrays.asList

@RunWith(JUnit4::class)
class DefaultPermissionServiceTest {

    private var subject: DefaultPermissionService? = null

    private var userContext: UserContext? = null
    private var permissionDataService: PermissionDataService? = null
    private var permissionCheckingService: PermissionCheckingService? = null
    private var expectedCredential: Credential? = null
    private var expectedCredentialVersion: CredentialVersion? = null
    private var userContextHolder: UserContextHolder? = null

    private fun <T> any(type: Class<T>): T = Mockito.any<T>(type)

    @Before
    fun beforeEach() {
        userContext = mock(UserContext::class.java)
        `when`(userContext!!.actor).thenReturn(USER_NAME)
        expectedCredential = Credential(CREDENTIAL_NAME)
        expectedCredentialVersion = PasswordCredentialVersion(CREDENTIAL_NAME)

        permissionDataService = mock(PermissionDataService::class.java)
        permissionCheckingService = mock(PermissionCheckingService::class.java)
        `when`(permissionCheckingService?.hasPermission(anyString(), anyString(), any(PermissionOperation::class.java)))
            .thenReturn(true)

        userContextHolder = mock(UserContextHolder::class.java)
        `when`(userContextHolder!!.userContext).thenReturn(userContext)
        subject = DefaultPermissionService(permissionDataService!!, permissionCheckingService!!, userContextHolder!!)
    }

    @Test
    fun getAllowedOperations_getsAllowedOperationsUsingPermissionsDataService() {
        val expectedOperations = Lists.newArrayList(PermissionOperation.READ)
        `when`(permissionDataService!!.getAllowedOperations(CREDENTIAL_NAME, USER_NAME))
            .thenReturn(expectedOperations)

        val foundOperations = subject!!
            .getAllowedOperationsForLogging(CREDENTIAL_NAME, USER_NAME)

        assertThat<List<PermissionOperation>>(expectedOperations, equalTo(foundOperations))
    }

    @Test
    fun saveAccessControlEntries_whenThereAreNoChanges_doesNothing() {
        val expectedEntries = newArrayList<PermissionEntry>()
        subject!!.savePermissionsForUser(expectedEntries)

        verify(permissionDataService, never())?.savePermissionsWithLogging(any<List<PermissionEntry>>())
    }

    @Test
    fun saveAccessControlEntries_withEntries_delegatesToDataService() {
        `when`(permissionCheckingService!!.userAllowedToOperateOnActor(eq(USER_NAME))).thenReturn(true)
        val expectedEntries = newArrayList(PermissionEntry(USER_NAME, "test-path", PermissionOperation.READ))
        subject!!.savePermissionsForUser(expectedEntries)

        verify(permissionDataService)?.savePermissionsWithLogging(expectedEntries)
    }

    @Test
    fun saveAccessControlEntries_whenCredentialHasACEs_shouldCallVerifyAclWritePermission() {
        `when`(permissionCheckingService!!.userAllowedToOperateOnActor(eq(USER_NAME))).thenReturn(true)
        val entries = newArrayList<PermissionEntry>()
        entries.add(PermissionEntry(USER_NAME, "test-path", asList(PermissionOperation.WRITE_ACL)))

        subject!!.savePermissionsForUser(entries)

        verify(permissionCheckingService)?.hasPermission(USER_NAME, "test-path", PermissionOperation.WRITE_ACL)
    }

    @Test
    fun saveAccessControlEntries_whenCredentialHasNoACEs_shouldDoNothing() {
        val entries = newArrayList<PermissionEntry>()

        subject!!.savePermissionsForUser(entries)

        verify(permissionCheckingService, never())?.hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.WRITE_ACL)
    }

    @Test
    fun saveAccessControlEntries_whenUserCantWrite_throws() {
        `when`(permissionCheckingService!!.userAllowedToOperateOnActor(eq(USER_NAME))).thenReturn(true)
        `when`(permissionCheckingService!!.hasPermission(USER_NAME, "test-path", PermissionOperation.WRITE_ACL))
            .thenReturn(false)
        val expectedEntries = newArrayList(PermissionEntry(USER_NAME, "test-path", PermissionOperation.READ))

        try {
            subject!!.savePermissionsForUser(expectedEntries)
            fail("expected exception")
        } catch (e: EntryNotFoundException) {
            assertThat(e.message, IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS))
        }
    }

    @Test
    fun setPermissions_whenThereIsNoUserContext_itProceedsWithoutCheckingForWriteAccess() {
        `when`(userContextHolder!!.userContext).thenReturn(null)
        `when`(permissionCheckingService!!.userAllowedToOperateOnActor(eq(USER_NAME))).thenReturn(true)

        val expectedEntries = newArrayList(PermissionEntry(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ))
        subject!!.savePermissions(expectedEntries)

        verify(permissionDataService)?.savePermissions(expectedEntries)
    }

    @Test
    fun getAccessControlList_whenUserCantRead_throws() {
        val expectedPermissionEntries = ArrayList<PermissionEntry>().toMutableList()
        `when`(permissionDataService!!.getPermissions(expectedCredential!!))
            .thenReturn(expectedPermissionEntries)
        val foundPermissionEntries = subject!!.getPermissions(expectedCredentialVersion)

        assertThat(foundPermissionEntries, equalTo(expectedPermissionEntries))
    }

    @Test
    fun findPermissionByPathAndActor_whenGivenPathAndActor_returnsPermissionData() {
        `when`(permissionCheckingService!!.hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ_ACL))
            .thenReturn(true)

        val actor = "some-actor"

        val expectedPermissionData = PermissionData(CREDENTIAL_NAME, actor)

        `when`(permissionDataService!!.findByPathAndActor(CREDENTIAL_NAME, actor))
            .thenReturn(expectedPermissionData)

        assertThat(subject!!.findByPathAndActor(CREDENTIAL_NAME, actor), equalTo(expectedPermissionData))
    }

    @Test
    fun findPermissionByNestedPathAndActor_whenAccessedByUserWithREADACL_returnPermissionData() {
        `when`(permissionCheckingService!!.hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ_ACL))
            .thenReturn(true)

        val actor = "some-actor"
        val path = "$CREDENTIAL_NAME/foo"

        val expectedPermissionData = PermissionData(path, actor)

        `when`(permissionDataService!!.findByPathAndActor(path, actor))
            .thenReturn(expectedPermissionData)

        assertThat(subject!!.findByPathAndActor(path, actor), equalTo(expectedPermissionData))
    }

    @Test
    fun findPermissionByPathAndActor_whenAccessedByAUserWithoutREADACL_throwsAnException() {
        `when`(permissionCheckingService!!.hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ_ACL))
            .thenReturn(false)

        val actor = "some-actor"

        assertThatThrownBy { subject!!.findByPathAndActor(CREDENTIAL_NAME, actor) }.isInstanceOf(EntryNotFoundException::class.java)
    }

    @Test
    fun getAccessControlList_delegatesToDataService() {
        `when`(permissionCheckingService!!.hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ_ACL))
            .thenReturn(false)
        val expectedPermissionEntries = newArrayList<PermissionEntry>()
        `when`(permissionDataService!!.getPermissions(expectedCredential!!))
            .thenReturn(expectedPermissionEntries)

        try {
            subject!!.getPermissions(expectedCredentialVersion)
            fail()
        } catch (e: EntryNotFoundException) {
            assertThat(e.message, IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS))
        }
    }

    @Test
    fun deleteAccessControlEntry_whenTheUserHasPermission_delegatesToDataService() {
        `when`(permissionCheckingService!!.hasPermission(userContext!!.actor!!, CREDENTIAL_NAME, PermissionOperation.WRITE_ACL))
            .thenReturn(true)
        `when`(permissionCheckingService!!.userAllowedToOperateOnActor("other-actor"))
            .thenReturn(true)
        `when`(permissionDataService!!.deletePermissions(CREDENTIAL_NAME, "other-actor"))
            .thenReturn(true)
        val result = subject!!.deletePermissions(CREDENTIAL_NAME, "other-actor")

        assertThat(result, equalTo(true))
    }

    @Test
    fun deleteAccessControlEntry_whenTheUserLacksPermission_throwsAnException() {
        `when`(permissionCheckingService!!.hasPermission(userContext!!.actor!!, CREDENTIAL_NAME, PermissionOperation.WRITE_ACL))
            .thenReturn(false)
        `when`(permissionDataService!!.deletePermissions(CREDENTIAL_NAME, "other-actor"))
            .thenReturn(true)
        try {
            subject!!.deletePermissions(CREDENTIAL_NAME, "other-actor")
            fail("should throw")
        } catch (e: EntryNotFoundException) {
            assertThat(e.message, IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS))
        }
    }

    @Test
    fun deleteAccessControlEntry_whenTheUserIsTheSameAsActor_throwsAnException() {
        `when`(permissionCheckingService!!.hasPermission(userContext!!.actor!!, CREDENTIAL_NAME, PermissionOperation.WRITE_ACL))
            .thenReturn(true)
        `when`(permissionDataService!!.deletePermissions(CREDENTIAL_NAME, userContext!!.actor!!))
            .thenReturn(true)
        try {
            subject!!.deletePermissions(CREDENTIAL_NAME, userContext!!.actor!!)
            fail("should throw")
        } catch (iaoe: InvalidPermissionOperationException) {
            assertThat(iaoe.message, IsEqual.equalTo(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION))
        }
    }

    companion object {

        private val CREDENTIAL_NAME = "/test/credential"
        private val USER_NAME = "test-actor"
    }
}

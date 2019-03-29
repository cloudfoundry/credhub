package org.cloudfoundry.credhub.handlers

import com.google.common.collect.Lists
import com.google.common.collect.Lists.newArrayList
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.data.CredentialDataService
import org.cloudfoundry.credhub.data.PermissionData
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData
import org.cloudfoundry.credhub.requests.PermissionEntry
import org.cloudfoundry.credhub.requests.PermissionsRequest
import org.cloudfoundry.credhub.requests.PermissionsV2Request
import org.cloudfoundry.credhub.services.DefaultPermissionedCredentialService
import org.cloudfoundry.credhub.services.PermissionCheckingService
import org.cloudfoundry.credhub.services.PermissionService
import org.cloudfoundry.credhub.views.PermissionsV2View
import org.hamcrest.CoreMatchers.equalTo
import org.junit.Assert.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.eq
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.util.ArrayList

@RunWith(JUnit4::class)
class DefaultPermissionsV2HandlerTest {
    private val credential = Credential(CREDENTIAL_NAME)
    private val credentialVersion = PasswordCredentialVersion(PasswordCredentialVersionData(CREDENTIAL_NAME))
    private lateinit var subject: DefaultPermissionsV2Handler
    private lateinit var permissionService: PermissionService
    private lateinit var permissionCheckingService: PermissionCheckingService
    private lateinit var credentialDataService: CredentialDataService
    private lateinit var permissionedCredentialService: DefaultPermissionedCredentialService
    private lateinit var permissionsRequest: PermissionsRequest
    private lateinit var permissionsV2Request: PermissionsV2Request

    @Before
    fun beforeEach() {
        permissionService = mock<PermissionService>(PermissionService::class.java)
        permissionCheckingService = mock<PermissionCheckingService>(PermissionCheckingService::class.java)
        credentialDataService = mock<CredentialDataService>(CredentialDataService::class.java)
        permissionedCredentialService = mock<DefaultPermissionedCredentialService>(DefaultPermissionedCredentialService::class.java)
        subject = DefaultPermissionsV2Handler(permissionService)

        permissionsRequest = mock<PermissionsRequest>(PermissionsRequest::class.java)
        permissionsV2Request = PermissionsV2Request()

        `when`<CredentialVersion>(permissionedCredentialService.findMostRecent(CREDENTIAL_NAME)).thenReturn(credentialVersion)
        `when`<Credential>(credentialDataService.find(any<String>(String::class.java))).thenReturn(credential)
    }

    @Test
    fun findByPathAndActor_whenGivenAPathAndActor_returnsPermissionsV2View() {
        val path = "some-path"
        val actor = "some-actor"

        val expectedPermissionsV2View = PermissionsV2View(
            path,
            emptyList(),
            actor,
            null
        )

        `when`<PermissionData>(permissionService.findByPathAndActor(path, actor))
            .thenReturn(PermissionData(path, actor))

        val actualPermissionsV2View = subject.findByPathAndActor(path, actor)
        assertThat<PermissionsV2View>(
            actualPermissionsV2View,
            equalTo<PermissionsV2View>(expectedPermissionsV2View)
        )
    }

    @Test(expected = IllegalStateException::class)
    fun setPermissionsCalledWithOnePermission_whenPermissionServiceReturnsMultiplePermissions_throwsException() {
        `when`<Boolean>(permissionCheckingService.hasPermission(any<String>(String::class.java), eq<String>(CREDENTIAL_NAME), eq<PermissionOperation>(PermissionOperation.WRITE_ACL))).thenReturn(true)
        `when`<Boolean>(permissionCheckingService.userAllowedToOperateOnActor(ACTOR_NAME)).thenReturn(true)

        val permissionList = ArrayList<PermissionData>()
        permissionList.add(PermissionData())
        permissionList.add(PermissionData())

        `when`<List<PermissionData>>(permissionService.savePermissionsForUser(any<List<PermissionEntry>>())).thenReturn(permissionList)

        val operations = newArrayList<PermissionOperation>(PermissionOperation.READ, PermissionOperation.WRITE)
        val permissionEntry = PermissionEntry(ACTOR_NAME, "test-path", operations)

        val preexistingPermissionEntry = PermissionEntry(ACTOR_NAME2, "test-path", Lists.newArrayList(PermissionOperation.READ))
        val expectedControlList = newArrayList<PermissionEntry>(permissionEntry, preexistingPermissionEntry)

        `when`<List<PermissionEntry>>(permissionService.getPermissions(credentialVersion)).thenReturn(expectedControlList)

        permissionsV2Request.operations = operations
        permissionsV2Request.path = CREDENTIAL_NAME

        try {
            subject.writePermissions(permissionsV2Request)
        } catch (e: Exception) {
            assertThat<String>(e.message, equalTo<String>(DefaultPermissionsV2Handler.INVALID_NUMBER_OF_PERMISSIONS))
            throw e
        }
    }

    companion object {
        private val CREDENTIAL_NAME = "/test-credential"
        private val ACTOR_NAME = "test-actor"
        private val ACTOR_NAME2 = "someone-else"
        private val USER = "test-user"
    }
}

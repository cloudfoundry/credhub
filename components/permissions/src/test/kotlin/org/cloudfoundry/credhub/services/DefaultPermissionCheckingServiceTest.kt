package org.cloudfoundry.credhub.services

import junit.framework.TestCase.assertEquals
import junit.framework.TestCase.assertFalse
import junit.framework.TestCase.assertTrue
import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.PermissionOperation.DELETE
import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.PermissionOperation.READ_ACL
import org.cloudfoundry.credhub.PermissionOperation.WRITE
import org.cloudfoundry.credhub.PermissionOperation.WRITE_ACL
import org.cloudfoundry.credhub.auth.UserContext
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.data.PermissionDataService
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.springframework.test.util.ReflectionTestUtils
import java.util.UUID

@RunWith(JUnit4::class)
class DefaultPermissionCheckingServiceTest {

    private var subject: DefaultPermissionCheckingService? = null

    private var userContext: UserContext? = null
    private var permissionDataService: PermissionDataService? = null

    @Before
    fun beforeEach() {
        userContext = mock(UserContext::class.java)
        `when`(userContext!!.actor).thenReturn("test-actor")

        permissionDataService = mock(PermissionDataService::class.java)
        val userContextHolder = UserContextHolder()
        userContextHolder.userContext = userContext
        subject = DefaultPermissionCheckingService(permissionDataService!!, userContextHolder)
    }

    @Test
    fun hasPermission_returnsWhetherTheUserHasThePermissionForTheCredential() {
        initializeEnforcement(true)

        assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, true)
        assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, false)
        assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, true)
        assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, false)
        assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, READ, true)
        assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, READ, false)
        assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, WRITE, true)
        assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, WRITE, false)
        assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, DELETE, true)
        assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, DELETE, false)
    }

    @Test
    fun hasPermission_ifPermissionsNotEnforced_returnsTrue() {
        initializeEnforcement(false)

        assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, true)
        assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, false)
        assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, true)
        assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, false)
        assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ, true)
        assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ, false)
        assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE, true)
        assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE, false)
        assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, DELETE, true)
        assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, DELETE, false)
    }

    @Test
    fun hasPermission_ifUUIDisNull_returnsFalse() {
        initializeEnforcement(true)
        assertFalse(subject!!.hasPermission("test-actor", UUID.randomUUID(), READ))
    }

    @Test
    fun validDeleteOperation_withoutEnforcement_returnsTrue() {
        initializeEnforcement(false)

        assertTrue(
            subject!!.userAllowedToOperateOnActor("test-actor"),
        )
    }

    @Test
    fun validDeleteOperation_withEnforcement_whenTheUserDeletesOthersACL_returnsTrue() {
        initializeEnforcement(true)

        assertTrue(
            subject!!.userAllowedToOperateOnActor("random-actor"),
        )
    }

    @Test
    fun validDeleteOperation_withEnforcement_whenTheUserDeletesOwnACL_returnsFalse() {
        initializeEnforcement(true)

        assertFalse(
            subject!!.userAllowedToOperateOnActor("test-actor"),
        )
    }

    @Test
    fun validDeleteOperation_withEnforcement_whenAclUserIsNull_returnsFalse() {
        initializeEnforcement(true)
        `when`(userContext!!.actor).thenReturn(null)

        assertFalse(
            subject!!.userAllowedToOperateOnActor("test-actor"),
        )
    }

    @Test
    fun validDeleteOperation_withEnforcement_whenAclUserAndActorAreNull_returnsFalse() {
        val input: String? = null
        initializeEnforcement(true)
        `when`(userContext!!.actor).thenReturn(null)

        assertFalse(subject!!.userAllowedToOperateOnActor(input))
    }

    @Test
    fun findAllPathsByActor_whenActorHasPermissions_returnsPaths() {
        val paths = HashSet(listOf(CREDENTIAL_NAME))
        `when`(permissionDataService!!.findAllPathsByActor("test-actor"))
            .thenReturn(paths)

        assertEquals(subject!!.findAllPathsByActor("test-actor"), paths)
    }

    @Test
    fun findAllPathsByActor_whenActorDoesNotHavePermissions_returnsEmptySet() {
        val paths = HashSet<String>()
        `when`(permissionDataService!!.findAllPathsByActor("test-actor"))
            .thenReturn(paths)

        assertEquals(subject!!.findAllPathsByActor("test-actor"), paths)
    }

    private fun initializeEnforcement(enabled: Boolean) {
        ReflectionTestUtils
            .setField(subject, DefaultPermissionCheckingService::class.java, "enforcePermissions", enabled, Boolean::class.javaPrimitiveType)
    }

    private fun assertConditionallyHasPermission(
        user: String,
        credentialName: String,
        permission: PermissionOperation,
        isGranted: Boolean,
    ) {
        `when`(
            permissionDataService!!
                .hasPermission(user, credentialName, permission),
        )
            .thenReturn(isGranted)

        assertThat(subject!!.hasPermission(user, credentialName, permission), equalTo(isGranted))
    }

    private fun assertAlwaysHasPermission(
        user: String,
        credentialName: String,
        permission: PermissionOperation,
        isGranted: Boolean,
    ) {
        `when`(
            permissionDataService!!
                .hasPermission(user, credentialName, permission),
        )
            .thenReturn(isGranted)

        assertThat(subject!!.hasPermission(user, credentialName, permission), equalTo(true))
    }

    companion object {

        private val CREDENTIAL_NAME = "/test/credential"
    }
}

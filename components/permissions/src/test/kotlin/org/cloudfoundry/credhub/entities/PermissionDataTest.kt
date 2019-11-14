package org.cloudfoundry.credhub.entities

import java.util.Arrays

import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.data.PermissionData
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue

@RunWith(JUnit4::class)
class PermissionDataTest {

    private var permissionData: PermissionData? = null

    @Before
    @Throws(Exception::class)
    fun setUp() {
        permissionData = PermissionData()
    }

    @Test
    fun hasPermission_withPermissions_ReturnsHasPermission() {
        assertFalse(permissionData!!.hasPermission(PermissionOperation.READ))
        assertFalse(permissionData!!.hasPermission(PermissionOperation.WRITE))
        assertFalse(permissionData!!.hasPermission(PermissionOperation.DELETE))
        assertFalse(permissionData!!.hasPermission(PermissionOperation.READ_ACL))
        assertFalse(permissionData!!.hasPermission(PermissionOperation.WRITE_ACL))
        permissionData!!.enableOperations(Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.DELETE, PermissionOperation.READ_ACL, PermissionOperation.WRITE_ACL))
        assertTrue(permissionData!!.hasPermission(PermissionOperation.READ))
        assertTrue(permissionData!!.hasPermission(PermissionOperation.WRITE))
        assertTrue(permissionData!!.hasPermission(PermissionOperation.DELETE))
        assertTrue(permissionData!!.hasPermission(PermissionOperation.READ_ACL))
        assertTrue(permissionData!!.hasPermission(PermissionOperation.WRITE_ACL))
    }
}

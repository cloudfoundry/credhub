package org.cloudfoundry.credhub.entities

import org.cloudfoundry.credhub.PermissionOperation
import org.cloudfoundry.credhub.data.PermissionData
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Arrays

class PermissionDataTest {
    private var permissionData: PermissionData? = null

    @BeforeEach
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
        permissionData!!.enableOperations(
            Arrays.asList(
                PermissionOperation.READ,
                PermissionOperation.WRITE,
                PermissionOperation.DELETE,
                PermissionOperation.READ_ACL,
                PermissionOperation.WRITE_ACL,
            ),
        )
        assertTrue(permissionData!!.hasPermission(PermissionOperation.READ))
        assertTrue(permissionData!!.hasPermission(PermissionOperation.WRITE))
        assertTrue(permissionData!!.hasPermission(PermissionOperation.DELETE))
        assertTrue(permissionData!!.hasPermission(PermissionOperation.READ_ACL))
        assertTrue(permissionData!!.hasPermission(PermissionOperation.WRITE_ACL))
    }
}

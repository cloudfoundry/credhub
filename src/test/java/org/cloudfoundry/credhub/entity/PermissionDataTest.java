package org.cloudfoundry.credhub.entity;

import org.cloudfoundry.credhub.request.PermissionOperation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Arrays;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(JUnit4.class)
public class PermissionDataTest {

  private PermissionData permissionData;

  @Before
  public void setUp() throws Exception {
    permissionData = new PermissionData();
  }

  @Test
  public void hasPermission_withPermissions_ReturnsHasPermission() {
    assertFalse(permissionData.hasPermission(PermissionOperation.READ));
    assertFalse(permissionData.hasPermission(PermissionOperation.WRITE));
    assertFalse(permissionData.hasPermission(PermissionOperation.DELETE));
    assertFalse(permissionData.hasPermission(PermissionOperation.READ_ACL));
    assertFalse(permissionData.hasPermission(PermissionOperation.WRITE_ACL));
    permissionData.enableOperations(Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.DELETE, PermissionOperation.READ_ACL, PermissionOperation.WRITE_ACL));
    assertTrue(permissionData.hasPermission(PermissionOperation.READ));
    assertTrue(permissionData.hasPermission(PermissionOperation.WRITE));
    assertTrue(permissionData.hasPermission(PermissionOperation.DELETE));
    assertTrue(permissionData.hasPermission(PermissionOperation.READ_ACL));
    assertTrue(permissionData.hasPermission(PermissionOperation.WRITE_ACL));
  }
}

package io.pivotal.security.entity;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Arrays;

import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
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
    assertFalse(permissionData.hasPermission(READ));
    assertFalse(permissionData.hasPermission(WRITE));
    assertFalse(permissionData.hasPermission(DELETE));
    assertFalse(permissionData.hasPermission(READ_ACL));
    assertFalse(permissionData.hasPermission(WRITE_ACL));
    permissionData.enableOperations(Arrays.asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL));
    assertTrue(permissionData.hasPermission(READ));
    assertTrue(permissionData.hasPermission(WRITE));
    assertTrue(permissionData.hasPermission(DELETE));
    assertTrue(permissionData.hasPermission(READ_ACL));
    assertTrue(permissionData.hasPermission(WRITE_ACL));
  }
}

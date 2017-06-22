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
public class AccessEntryDataTest {

  private AccessEntryData accessEntryData;

  @Before
  public void setUp() throws Exception {
    accessEntryData = new AccessEntryData();
  }

  @Test
  public void hasPermission_withPermissions_ReturnsHasPermission() {
    assertFalse(accessEntryData.hasPermission(READ));
    assertFalse(accessEntryData.hasPermission(WRITE));
    assertFalse(accessEntryData.hasPermission(DELETE));
    assertFalse(accessEntryData.hasPermission(READ_ACL));
    assertFalse(accessEntryData.hasPermission(WRITE_ACL));
    accessEntryData.enableOperations(Arrays.asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL));
    assertTrue(accessEntryData.hasPermission(READ));
    assertTrue(accessEntryData.hasPermission(WRITE));
    assertTrue(accessEntryData.hasPermission(DELETE));
    assertTrue(accessEntryData.hasPermission(READ_ACL));
    assertTrue(accessEntryData.hasPermission(WRITE_ACL));
  }
}

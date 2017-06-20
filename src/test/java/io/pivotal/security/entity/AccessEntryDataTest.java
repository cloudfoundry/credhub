package io.pivotal.security.entity;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Arrays;

import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
import static org.junit.Assert.assertTrue;

@RunWith(JUnit4.class)
public class AccessEntryDataTest {

  @Test
  public void hasPermission_withReadPermission_ReturnsHasReadPermission() {
    AccessEntryData accessEntryData = new AccessEntryData();
    accessEntryData.enableOperations(Arrays.asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL));
    assertTrue(accessEntryData.hasPermission(READ));
    assertTrue(accessEntryData.hasPermission(WRITE));
    assertTrue(accessEntryData.hasPermission(DELETE));
    assertTrue(accessEntryData.hasPermission(READ_ACL));
    assertTrue(accessEntryData.hasPermission(WRITE_ACL));
  }
}

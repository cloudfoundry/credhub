package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.request.PermissionOperation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.test.util.ReflectionTestUtils;

import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class PermissionServiceTest {
  private static final String CREDENTIAL_NAME = "/test/credential";

  private PermissionService subject;

  private UserContext userContext;
  private PermissionsDataService permissionsDataService;

  @Before
  public void beforeEach() {
    userContext = mock(UserContext.class);
    when(userContext.getAclUser()).thenReturn("test-actor");

    permissionsDataService = mock(PermissionsDataService.class);

    subject = new PermissionService(permissionsDataService);
  }

  @Test
  public void hasPermission_returnsWhetherTheUserHasThePermissionForTheCredential(){
    initializeEnforcement(true);

    assertHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, true);
    assertHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, false);
    assertHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, true);
    assertHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, false);
    assertHasPermission("test-actor", CREDENTIAL_NAME, READ, true);
    assertHasPermission("test-actor", CREDENTIAL_NAME, READ, false);
    assertHasPermission("test-actor", CREDENTIAL_NAME, WRITE, true);
    assertHasPermission("test-actor", CREDENTIAL_NAME, WRITE, false);
    assertHasPermission("test-actor", CREDENTIAL_NAME, DELETE, true);
    assertHasPermission("test-actor", CREDENTIAL_NAME, DELETE, false);
  }

  @Test
  public void hasPermission_ifPermissionsNotEnforced_returnsTrue(){
    initializeEnforcement(false);

    assertHasPermissionWithoutEnforcement("test-actor", CREDENTIAL_NAME, READ_ACL, true);
    assertHasPermissionWithoutEnforcement("test-actor", CREDENTIAL_NAME, READ_ACL, false);
    assertHasPermissionWithoutEnforcement("test-actor", CREDENTIAL_NAME, WRITE_ACL, true);
    assertHasPermissionWithoutEnforcement("test-actor", CREDENTIAL_NAME, WRITE_ACL, false);
    assertHasPermissionWithoutEnforcement("test-actor", CREDENTIAL_NAME, READ, true);
    assertHasPermissionWithoutEnforcement("test-actor", CREDENTIAL_NAME, READ, false);
    assertHasPermissionWithoutEnforcement("test-actor", CREDENTIAL_NAME, WRITE, true);
    assertHasPermissionWithoutEnforcement("test-actor", CREDENTIAL_NAME, WRITE, false);
    assertHasPermissionWithoutEnforcement("test-actor", CREDENTIAL_NAME, DELETE, true);
    assertHasPermissionWithoutEnforcement("test-actor", CREDENTIAL_NAME, DELETE, false);
  }

  @Test
  public void validDeleteOperation_withoutEnforcement_returnsTrue() {
    initializeEnforcement(false);

    assertTrue(subject.validAclUpdateOperation(userContext, "test-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenTheUserDeletesOthersACL_returnsTrue() {
    initializeEnforcement(true);

    assertTrue(subject.validAclUpdateOperation(userContext, "random-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenTheUserDeletesOwnACL_returnsFalse() {
    initializeEnforcement(true);

    assertFalse(subject.validAclUpdateOperation(userContext, "test-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenAclUserIsNull_returnsFalse() {
    initializeEnforcement(true);
    when(userContext.getAclUser()).thenReturn(null);

    assertFalse(subject.validAclUpdateOperation(userContext, "test-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenAclUserAndActorAreNull_returnsFalse() {
    initializeEnforcement(true);
    when(userContext.getAclUser()).thenReturn(null);

    assertFalse(subject.validAclUpdateOperation(userContext, null));
  }

  private void initializeEnforcement(boolean enabled) {
    ReflectionTestUtils
        .setField(subject, PermissionService.class, "enforcePermissions", enabled, boolean.class);
  }

  private void assertHasPermission(String user, String credentialName,
      PermissionOperation permission, boolean isGranted) {
    when(permissionsDataService
        .hasPermission(user, credentialName, permission))
        .thenReturn(isGranted);

    assertThat(subject.hasPermission(user, credentialName, permission), equalTo(isGranted));
  }

  private void assertHasPermissionWithoutEnforcement(String user, String credentialName,
      PermissionOperation permission, boolean isGranted) {
    when(permissionsDataService
        .hasPermission(user, credentialName, permission))
        .thenReturn(isGranted);

    assertThat(subject.hasPermission(user, credentialName, permission), equalTo(true));
  }
}

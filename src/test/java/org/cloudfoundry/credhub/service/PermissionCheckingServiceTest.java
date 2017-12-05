package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.test.util.ReflectionTestUtils;

import static org.cloudfoundry.credhub.request.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ_ACL;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE_ACL;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class PermissionCheckingServiceTest {
  private static final String CREDENTIAL_NAME = "/test/credential";

  private PermissionCheckingService subject;

  private UserContext userContext;
  private PermissionDataService permissionDataService;
  private Credential expectedCredential;

  @Before
  public void beforeEach() {
    userContext = mock(UserContext.class);
    when(userContext.getActor()).thenReturn("test-actor");

    permissionDataService = mock(PermissionDataService.class);
    UserContextHolder userContextHolder = new UserContextHolder();
    userContextHolder.setUserContext(userContext);
    subject = new PermissionCheckingService(permissionDataService, userContextHolder);
  }

  @Test
  public void hasPermission_returnsWhetherTheUserHasThePermissionForTheCredential(){
    initializeEnforcement(true);
    when(permissionDataService.hasNoDefinedAccessControl(CREDENTIAL_NAME)).thenReturn(false);

    assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, true);
    assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, false);
    assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, true);
    assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, false);
    assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, READ, true);
    assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, READ, false);
    assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, WRITE, true);
    assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, WRITE, false);
    assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, DELETE, true);
    assertConditionallyHasPermission("test-actor", CREDENTIAL_NAME, DELETE, false);
  }

  @Test
  public void hasPermission_ifPermissionsNotEnforced_returnsTrue(){
    initializeEnforcement(false);
    when(permissionDataService.hasNoDefinedAccessControl(CREDENTIAL_NAME)).thenReturn(false);

    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, true);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, false);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, true);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, false);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ, true);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ, false);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE, true);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE, false);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, DELETE, true);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, DELETE, false);
  }

  @Test
  public void hasPermission_whenNoDefinedAccessControl_returnsTrue() {
    initializeEnforcement(true);
    when(permissionDataService.hasNoDefinedAccessControl(CREDENTIAL_NAME)).thenReturn(true);

    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, true);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ_ACL, false);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, true);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE_ACL, false);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ, true);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, READ, false);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE, true);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, WRITE, false);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, DELETE, true);
    assertAlwaysHasPermission("test-actor", CREDENTIAL_NAME, DELETE, false);
  }
  @Test
  public void validDeleteOperation_withoutEnforcement_returnsTrue() {
    initializeEnforcement(false);

    assertTrue(
        subject.userAllowedToOperateOnActor("test-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenTheUserDeletesOthersACL_returnsTrue() {
    initializeEnforcement(true);

    assertTrue(
        subject.userAllowedToOperateOnActor("random-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenTheUserDeletesOwnACL_returnsFalse() {
    initializeEnforcement(true);

    assertFalse(
        subject.userAllowedToOperateOnActor("test-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenAclUserIsNull_returnsFalse() {
    initializeEnforcement(true);
    when(userContext.getActor()).thenReturn(null);

    assertFalse(
        subject.userAllowedToOperateOnActor("test-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenAclUserAndActorAreNull_returnsFalse() {
    initializeEnforcement(true);
    when(userContext.getActor()).thenReturn(null);

    assertFalse(subject.userAllowedToOperateOnActor(null));
  }

  private void initializeEnforcement(boolean enabled) {
    ReflectionTestUtils
        .setField(subject, PermissionCheckingService.class, "enforcePermissions", enabled, boolean.class);
  }

  private void assertConditionallyHasPermission(String user, String credentialName,
      PermissionOperation permission, boolean isGranted) {
    when(permissionDataService
        .hasPermission(user, credentialName, permission))
        .thenReturn(isGranted);

    assertThat(subject.hasPermission(user, credentialName, permission), equalTo(isGranted));
  }

  private void assertAlwaysHasPermission(String user, String credentialName,
      PermissionOperation permission, boolean isGranted) {
    when(permissionDataService
        .hasPermission(user, credentialName, permission))
        .thenReturn(isGranted);

    assertThat(subject.hasPermission(user, credentialName, permission), equalTo(true));
  }
}

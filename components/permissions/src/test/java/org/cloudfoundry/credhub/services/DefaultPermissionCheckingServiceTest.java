package org.cloudfoundry.credhub.services;

import java.util.Collections;
import java.util.HashSet;
import java.util.UUID;

import org.springframework.test.util.ReflectionTestUtils;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.cloudfoundry.credhub.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.PermissionOperation.READ;
import static org.cloudfoundry.credhub.PermissionOperation.READ_ACL;
import static org.cloudfoundry.credhub.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.PermissionOperation.WRITE_ACL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class DefaultPermissionCheckingServiceTest {

  private static final String CREDENTIAL_NAME = "/test/credential";

  private DefaultPermissionCheckingService subject;

  private UserContext userContext;
  private PermissionDataService permissionDataService;

  @Before
  public void beforeEach() {
    userContext = mock(UserContext.class);
    when(userContext.getActor()).thenReturn("test-actor");

    permissionDataService = mock(PermissionDataService.class);
    final UserContextHolder userContextHolder = new UserContextHolder();
    userContextHolder.setUserContext(userContext);
    subject = new DefaultPermissionCheckingService(permissionDataService, userContextHolder);
  }

  @Test
  public void hasPermission_returnsWhetherTheUserHasThePermissionForTheCredential() {
    initializeEnforcement(true);

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
  public void hasPermission_ifPermissionsNotEnforced_returnsTrue() {
    initializeEnforcement(false);

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
  public void hasPermission_ifUUIDisNull_returnsFalse() {
    initializeEnforcement(true);
    assertFalse(subject.hasPermission("test-actor", UUID.randomUUID(), READ));
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
    final String input = null;
    initializeEnforcement(true);
    when(userContext.getActor()).thenReturn(null);

    assertFalse(subject.userAllowedToOperateOnActor(input));
  }

  @Test
  public void findAllPathsByActor_whenActorHasPermissions_returnsPaths() {
    HashSet<String> paths = new HashSet<>(Collections.singletonList(CREDENTIAL_NAME));
    when(permissionDataService.findAllPathsByActor("test-actor"))
      .thenReturn(paths);

    assertEquals(subject.findAllPathsByActor("test-actor"), paths);
  }

  @Test
  public void findAllPathsByActor_whenActorDoesNotHavePermissions_returnsEmptySet() {
    HashSet<String> paths = new HashSet<>();
    when(permissionDataService.findAllPathsByActor("test-actor"))
      .thenReturn(paths);

    assertEquals(subject.findAllPathsByActor("test-actor"), paths);
  }


  private void initializeEnforcement(final boolean enabled) {
    ReflectionTestUtils
      .setField(subject, DefaultPermissionCheckingService.class, "enforcePermissions", enabled, boolean.class);
  }

  private void assertConditionallyHasPermission(final String user, final String credentialName,
    final PermissionOperation permission, final boolean isGranted) {
    when(permissionDataService
      .hasPermission(user, credentialName, permission))
      .thenReturn(isGranted);

    assertThat(subject.hasPermission(user, credentialName, permission), equalTo(isGranted));
  }

  private void assertAlwaysHasPermission(final String user, final String credentialName,
    final PermissionOperation permission, final boolean isGranted) {
    when(permissionDataService
      .hasPermission(user, credentialName, permission))
      .thenReturn(isGranted);

    assertThat(subject.hasPermission(user, credentialName, permission), equalTo(true));
  }

}

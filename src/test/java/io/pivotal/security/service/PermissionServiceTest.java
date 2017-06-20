package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.test.util.ReflectionTestUtils;

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
  public void verifyAclReadPermission_withEnforcement_whenTheUserHasPermission_doesNothing() {
    initializeEnforcement(true);

    when(permissionsDataService.hasReadAclPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    subject.hasAclReadPermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void verifyAclReadPermission_withEnforcement_whenTheUserDoesNotHavePermission_throwsException() {
    initializeEnforcement(true);

    when(permissionsDataService.hasReadAclPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);


      assertFalse(subject.hasAclReadPermission(userContext, CREDENTIAL_NAME));
  }

  @Test
  public void verifyAclReadPermission_withoutEnforcement_whenTheUserHasPermission_doesNothing() {
    initializeEnforcement(false);

    when(permissionsDataService.hasReadAclPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    subject.hasAclReadPermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void verifyAclReadPermission_withoutEnforcement_whenTheUserDoesNotHavePermission_doesNothing() {
    initializeEnforcement(false);

    when(permissionsDataService.hasReadAclPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    subject.hasAclReadPermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void hasAclWritePermission_withEnforcement_whenTheUserHasPermission_returnsTrue() {
    initializeEnforcement(true);

    when(permissionsDataService.hasAclWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    assertThat(subject.hasAclWritePermission(userContext, CREDENTIAL_NAME), equalTo(true));
  }

  @Test
  public void hasAclWritePermission_withEnforcement_whenTheUserDoesNotHavePermission_returnsFalse() {
    initializeEnforcement(true);

    when(permissionsDataService.hasAclWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    assertThat(subject.hasAclWritePermission(userContext, CREDENTIAL_NAME), equalTo(false));
  }

  @Test
  public void hasAclWritePermission_withoutEnforcement_whenTheUserHasPermission_returnsTrue() {
    initializeEnforcement(false);

    when(permissionsDataService.hasAclWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    assertThat(subject.hasAclWritePermission(userContext, CREDENTIAL_NAME), equalTo(true));
  }

  @Test
  public void hasAclWritePermission_withoutEnforcement_whenTheUserDoesNotHavePermission_returnsTrue() {
    initializeEnforcement(false);

    when(permissionsDataService.hasAclWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    assertThat(subject.hasAclWritePermission(userContext, CREDENTIAL_NAME), equalTo(true));
  }

  @Test
  public void verifyCredentialWritePermission_withEnforcement_whenTheUserHasPermission_doesNothing() {
    initializeEnforcement(true);

    when(permissionsDataService.hasCredentialWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    subject.hasCredentialWritePermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void verifyCredentialWritePermission_withEnforcement_whenTheUserDoesNotHavePermission_throwsException() {
    initializeEnforcement(true);

    when(permissionsDataService.hasCredentialWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

      assertFalse(subject.hasCredentialWritePermission(userContext, CREDENTIAL_NAME));
  }

  @Test
  public void verifyCredentialWritePermission_withoutEnforcement_whenTheUserHasPermission_doesNothing() {
    initializeEnforcement(false);

    when(permissionsDataService.hasCredentialWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    subject.hasCredentialWritePermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void verifyCredentialWritePermission_withoutEnforcement_whenTheUserDoesNotHavePermission_doesNothing() {
    initializeEnforcement(false);

    when(permissionsDataService.hasCredentialWritePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    subject.hasCredentialWritePermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void hasCredentialReadPermission_withEnforcement_whenTheUserPermission_returnsTrue() {
    initializeEnforcement(true);

    when(permissionsDataService.hasReadPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    assertTrue(subject.hasCredentialReadPermission(userContext, CREDENTIAL_NAME));
  }

  @Test
  public void hasCredentialReadPermission_withEnforcement_whenTheUserDoesNotHavePermission_returnsFalse() {
    initializeEnforcement(true);

    when(permissionsDataService.hasReadPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    assertFalse(subject.hasCredentialReadPermission(userContext, CREDENTIAL_NAME));
  }

  @Test
  public void hasCredentialReadPermission_withoutEnforcement_whenTheUserHasPermission_returnsTrue() {
    initializeEnforcement(false);

    when(permissionsDataService.hasReadPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    assertTrue(subject.hasCredentialReadPermission(userContext, CREDENTIAL_NAME));
  }

  @Test
  public void hasCredentialReadPermission_withoutEnforcement_whenTheUserDoesNotHavePermission_returnsTrue() {
    initializeEnforcement(false);

    when(permissionsDataService.hasReadPermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    assertTrue(subject.hasCredentialReadPermission(userContext, CREDENTIAL_NAME));
  }

  @Test
  public void hasCredentialDeletePermission_withEnforcement_whenTheUserPermission_returnsTrue() {
    initializeEnforcement(true);

    when(permissionsDataService.hasCredentialDeletePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    assertTrue(subject.hasCredentialDeletePermission(userContext, CREDENTIAL_NAME));
  }

  @Test
  public void hasCredentialDeletePermission_withEnforcement_whenTheUserDoesNotHavePermission_returnsFalse() {
    initializeEnforcement(true);

    when(permissionsDataService.hasCredentialDeletePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    assertFalse(subject.hasCredentialDeletePermission(userContext, CREDENTIAL_NAME));
  }

  @Test
  public void hasCredentialDeletePermission_withoutEnforcement_whenTheUserHasPermission_returnsTrue() {
    initializeEnforcement(false);

    when(permissionsDataService.hasCredentialDeletePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(true);

    assertTrue(subject.hasCredentialDeletePermission(userContext, CREDENTIAL_NAME));
  }

  @Test
  public void hasCredentialDeletePermission_withoutEnforcement_whenTheUserDoesNotHavePermission_returnsTrue() {
    initializeEnforcement(false);

    when(permissionsDataService.hasCredentialDeletePermission("test-actor", CREDENTIAL_NAME))
        .thenReturn(false);

    assertTrue(subject.hasCredentialDeletePermission(userContext, CREDENTIAL_NAME));
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
}

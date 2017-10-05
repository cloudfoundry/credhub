package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import org.hamcrest.core.IsEqual;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class PermissionServiceTest {
  private static final String CREDENTIAL_NAME = "/test/credential";

  private PermissionService subject;

  private UserContext userContext;
  private PermissionsDataService permissionsDataService;
  private CredentialName expectedCredentialName;

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
    when(permissionsDataService.hasNoDefinedAccessControl(CREDENTIAL_NAME)).thenReturn(false);

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
    when(permissionsDataService.hasNoDefinedAccessControl(CREDENTIAL_NAME)).thenReturn(false);

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
    when(permissionsDataService.hasNoDefinedAccessControl(CREDENTIAL_NAME)).thenReturn(true);

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

    assertTrue(subject.userAllowedToOperateOnActor(userContext, "test-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenTheUserDeletesOthersACL_returnsTrue() {
    initializeEnforcement(true);

    assertTrue(subject.userAllowedToOperateOnActor(userContext, "random-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenTheUserDeletesOwnACL_returnsFalse() {
    initializeEnforcement(true);

    assertFalse(subject.userAllowedToOperateOnActor(userContext, "test-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenAclUserIsNull_returnsFalse() {
    initializeEnforcement(true);
    when(userContext.getAclUser()).thenReturn(null);

    assertFalse(subject.userAllowedToOperateOnActor(userContext, "test-actor"));
  }

  @Test
  public void validDeleteOperation_withEnforcement_whenAclUserAndActorAreNull_returnsFalse() {
    initializeEnforcement(true);
    when(userContext.getAclUser()).thenReturn(null);

    assertFalse(subject.userAllowedToOperateOnActor(userContext, null));
  }

  @Test
  public void getAllowedOperations_getsAllowedOperationsUsingPermissionsDataService() {
    ArrayList<PermissionOperation> expectedOperations = newArrayList(PermissionOperation.READ);
    when(permissionsDataService.getAllowedOperations(CREDENTIAL_NAME, "test-actor"))
        .thenReturn(expectedOperations);

    List<PermissionOperation> foundOperations = subject
        .getAllowedOperations(CREDENTIAL_NAME, "test-actor");

    assertThat(expectedOperations, equalTo(foundOperations));
  }

  @Test
  public void saveAccessControlEntries_delegatesToDataService() {
    ArrayList<PermissionEntry> expectedEntries = newArrayList();
    expectedCredentialName = new CredentialName(CREDENTIAL_NAME);
    subject.saveAccessControlEntries(expectedCredentialName, expectedEntries);

    verify(permissionsDataService).saveAccessControlEntries(expectedCredentialName, expectedEntries);
  }

  @Test
  public void getAccessControlList_delegatesToDataService() {
    List<PermissionEntry> expectedPermissionEntries = newArrayList();
    when(permissionsDataService.getAccessControlList(expectedCredentialName))
        .thenReturn(expectedPermissionEntries);
    List<PermissionEntry> foundPermissionEntries = subject.getAccessControlList(expectedCredentialName);

    assertThat(foundPermissionEntries, equalTo(expectedPermissionEntries));
  }

  @Test
  public void deleteAccessControlEntry_whenTheUserHasPermission_delegatesToDataService() {
    initializeEnforcement(true);

    when(permissionsDataService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(true);
    when(permissionsDataService.deleteAccessControlEntry(CREDENTIAL_NAME, "other-actor"))
        .thenReturn(true);
    boolean result = subject.deleteAccessControlEntry(userContext, CREDENTIAL_NAME, "other-actor");

    assertThat(result, equalTo(true));
  }

  @Test
  public void deleteAccessControlEntry_whenTheUserLacksPermission_throwsAnException() {
    initializeEnforcement(true);
    when(permissionsDataService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(false);
    when(permissionsDataService.deleteAccessControlEntry(CREDENTIAL_NAME, "other-actor"))
        .thenReturn(true);
    try {
      subject.deleteAccessControlEntry(userContext, CREDENTIAL_NAME, "other-actor");
      fail("should throw");
    } catch( EntryNotFoundException e ){
      assertThat(e.getMessage(), IsEqual.equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void deleteAccessControlEntry_whenTheUserIsTheSameAsActor_throwsAnException() {
    initializeEnforcement(true);
    when(permissionsDataService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(true);
    when(permissionsDataService.deleteAccessControlEntry(CREDENTIAL_NAME, userContext.getAclUser()))
        .thenReturn(true);
    try {
      subject.deleteAccessControlEntry(userContext, CREDENTIAL_NAME, userContext.getAclUser());
      fail("should throw");
    } catch( InvalidAclOperationException iaoe ){
      assertThat(iaoe.getMessage(), IsEqual.equalTo("error.acl.invalid_update_operation"));
    }
  }

  private void initializeEnforcement(boolean enabled) {
    ReflectionTestUtils
        .setField(subject, PermissionService.class, "enforcePermissions", enabled, boolean.class);
  }

  private void assertConditionallyHasPermission(String user, String credentialName,
      PermissionOperation permission, boolean isGranted) {
    when(permissionsDataService
        .hasPermission(user, credentialName, permission))
        .thenReturn(isGranted);

    assertThat(subject.hasPermission(user, credentialName, permission), equalTo(isGranted));
  }

  private void assertAlwaysHasPermission(String user, String credentialName,
      PermissionOperation permission, boolean isGranted) {
    when(permissionsDataService
        .hasPermission(user, credentialName, permission))
        .thenReturn(isGranted);

    assertThat(subject.hasPermission(user, credentialName, permission), equalTo(true));
  }
}

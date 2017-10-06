package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import org.hamcrest.core.IsEqual;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class PermissionServiceTest {

  private static final String CREDENTIAL_NAME = "/test/credential";
  private static final String USER_NAME = "test-actor";

  private PermissionService subject;

  private UserContext userContext;
  private PermissionsDataService permissionsDataService;
  private PermissionCheckingService permissionCheckingService;
  private Credential expectedCredential;

  @Before
  public void beforeEach() {
    userContext = mock(UserContext.class);
    when(userContext.getAclUser()).thenReturn(USER_NAME);
    expectedCredential = new Credential(CREDENTIAL_NAME);

    permissionsDataService = mock(PermissionsDataService.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    when(permissionCheckingService.hasPermission(anyString(), anyString(), any(PermissionOperation.class)))
        .thenReturn(true);

    subject = new PermissionService(permissionsDataService, permissionCheckingService);
  }

  @Test
  public void getAllowedOperations_getsAllowedOperationsUsingPermissionsDataService() {
    ArrayList<PermissionOperation> expectedOperations = newArrayList(PermissionOperation.READ);
    when(permissionsDataService.getAllowedOperations(CREDENTIAL_NAME, USER_NAME))
        .thenReturn(expectedOperations);

    List<PermissionOperation> foundOperations = subject
        .getAllowedOperationsForLogging(CREDENTIAL_NAME, USER_NAME);

    assertThat(expectedOperations, equalTo(foundOperations));
  }

  @Test
  public void saveAccessControlEntries_delegatesToDataService() {
    ArrayList<PermissionEntry> expectedEntries = newArrayList();
    subject.saveAccessControlEntries(userContext, expectedCredential, expectedEntries);

    verify(permissionsDataService).saveAccessControlEntries(expectedCredential, expectedEntries);
  }

  @Test
  public void saveAccessControlEntries_whenUserCantWrite_throws() {
    when(permissionCheckingService.hasPermission(USER_NAME, CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(false);
    ArrayList<PermissionEntry> expectedEntries = newArrayList();

    try {
      subject.saveAccessControlEntries(userContext, expectedCredential, expectedEntries);
      fail("expected exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), IsEqual.equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getAccessControlList_whenUserCantRead_throws() {
    List<PermissionEntry> expectedPermissionEntries = newArrayList();
    when(permissionsDataService.getAccessControlList(expectedCredential))
        .thenReturn(expectedPermissionEntries);
    List<PermissionEntry> foundPermissionEntries = subject.getAccessControlList(userContext, expectedCredential);

    assertThat(foundPermissionEntries, equalTo(expectedPermissionEntries));
  }

  @Test
  public void getAccessControlList_delegatesToDataService() {
    when(permissionCheckingService.hasPermission(USER_NAME, CREDENTIAL_NAME, READ_ACL))
        .thenReturn(false);
    List<PermissionEntry> expectedPermissionEntries = newArrayList();
    when(permissionsDataService.getAccessControlList(expectedCredential))
        .thenReturn(expectedPermissionEntries);

    try {
      subject.getAccessControlList(userContext, expectedCredential);
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), IsEqual.equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void deleteAccessControlEntry_whenTheUserHasPermission_delegatesToDataService() {
    when(permissionCheckingService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(true);
    when(permissionCheckingService.userAllowedToOperateOnActor(userContext, "other-actor"))
        .thenReturn(true);
    when(permissionsDataService.deleteAccessControlEntry(CREDENTIAL_NAME, "other-actor"))
        .thenReturn(true);
    boolean result = subject.deleteAccessControlEntry(userContext, CREDENTIAL_NAME, "other-actor");

    assertThat(result, equalTo(true));
  }

  @Test
  public void deleteAccessControlEntry_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(false);
    when(permissionsDataService.deleteAccessControlEntry(CREDENTIAL_NAME, "other-actor"))
        .thenReturn(true);
    try {
      subject.deleteAccessControlEntry(userContext, CREDENTIAL_NAME, "other-actor");
      fail("should throw");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), IsEqual.equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void deleteAccessControlEntry_whenTheUserIsTheSameAsActor_throwsAnException() {
    when(permissionCheckingService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(true);
    when(permissionsDataService.deleteAccessControlEntry(CREDENTIAL_NAME, userContext.getAclUser()))
        .thenReturn(true);
    try {
      subject.deleteAccessControlEntry(userContext, CREDENTIAL_NAME, userContext.getAclUser());
      fail("should throw");
    } catch (InvalidAclOperationException iaoe) {
      assertThat(iaoe.getMessage(), IsEqual.equalTo("error.acl.invalid_update_operation"));
    }
  }
}

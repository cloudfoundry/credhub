package org.cloudfoundry.credhub.services;

import java.util.List;

import com.google.common.collect.Lists;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.PermissionData;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException;
import org.cloudfoundry.credhub.requests.PermissionEntry;
import org.hamcrest.core.IsEqual;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class DefaultPermissionServiceTest {

  private static final String CREDENTIAL_NAME = "/test/credential";
  private static final String USER_NAME = "test-actor";

  private DefaultPermissionService subject;

  private UserContext userContext;
  private PermissionDataService permissionDataService;
  private PermissionCheckingService permissionCheckingService;
  private Credential expectedCredential;
  private CredentialVersion expectedCredentialVersion;
  private UserContextHolder userContextHolder;

  @Before
  public void beforeEach() {
    userContext = mock(UserContext.class);
    when(userContext.getActor()).thenReturn(USER_NAME);
    expectedCredential = new Credential(CREDENTIAL_NAME);
    expectedCredentialVersion = new PasswordCredentialVersion(CREDENTIAL_NAME);

    permissionDataService = mock(PermissionDataService.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    when(permissionCheckingService.hasPermission(anyString(), anyString(), any(PermissionOperation.class)))
      .thenReturn(true);

    userContextHolder = mock(UserContextHolder.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    subject = new DefaultPermissionService(permissionDataService, permissionCheckingService, userContextHolder);
  }

  @Test
  public void getAllowedOperations_getsAllowedOperationsUsingPermissionsDataService() {
    final List<PermissionOperation> expectedOperations = Lists.newArrayList(PermissionOperation.READ);
    when(permissionDataService.getAllowedOperations(CREDENTIAL_NAME, USER_NAME))
      .thenReturn(expectedOperations);

    final List<PermissionOperation> foundOperations = subject
      .getAllowedOperationsForLogging(CREDENTIAL_NAME, USER_NAME);

    assertThat(expectedOperations, equalTo(foundOperations));
  }

  @Test
  public void saveAccessControlEntries_whenThereAreNoChanges_doesNothing() {
    final List<PermissionEntry> expectedEntries = newArrayList();
    subject.savePermissionsForUser(expectedEntries);

    verify(permissionDataService, never()).savePermissionsWithLogging(any());
  }

  @Test
  public void saveAccessControlEntries_withEntries_delegatesToDataService() {
    when(permissionCheckingService.userAllowedToOperateOnActor(eq(USER_NAME))).thenReturn(true);
    final List<PermissionEntry> expectedEntries = newArrayList(new PermissionEntry(USER_NAME, "test-path", PermissionOperation.READ));
    subject.savePermissionsForUser(expectedEntries);

    verify(permissionDataService).savePermissionsWithLogging(expectedEntries);
  }

  @Test
  public void saveAccessControlEntries_whenCredentialHasACEs_shouldCallVerifyAclWritePermission() {
    when(permissionCheckingService.userAllowedToOperateOnActor(eq(USER_NAME))).thenReturn(true);
    final List<PermissionEntry> entries = newArrayList();
    entries.add(new PermissionEntry(USER_NAME, "test-path", asList(PermissionOperation.WRITE_ACL)));

    subject.savePermissionsForUser(entries);

    verify(permissionCheckingService).hasPermission(USER_NAME, "test-path", PermissionOperation.WRITE_ACL);
  }

  @Test
  public void saveAccessControlEntries_whenCredentialHasNoACEs_shouldDoNothing() {
    final List<PermissionEntry> entries = newArrayList();

    subject.savePermissionsForUser(entries);

    verify(permissionCheckingService, never()).hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.WRITE_ACL);
  }

  @Test
  public void saveAccessControlEntries_whenUserCantWrite_throws() {
    when(permissionCheckingService.userAllowedToOperateOnActor(eq(USER_NAME))).thenReturn(true);
    when(permissionCheckingService.hasPermission(USER_NAME, "test-path", PermissionOperation.WRITE_ACL))
      .thenReturn(false);
    final List<PermissionEntry> expectedEntries = newArrayList(new PermissionEntry(USER_NAME, "test-path", PermissionOperation.READ));

    try {
      subject.savePermissionsForUser(expectedEntries);
      fail("expected exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void setPermissions_whenThereIsNoUserContext_itProceedsWithoutCheckingForWriteAccess() {
    when(userContextHolder.getUserContext()).thenReturn(null);
    when(permissionCheckingService.userAllowedToOperateOnActor(eq(USER_NAME))).thenReturn(true);

    final List<PermissionEntry> expectedEntries = newArrayList(new PermissionEntry(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ));
    subject.savePermissions(expectedEntries);

    verify(permissionDataService).savePermissions(expectedEntries);
  }

  @Test
  public void getAccessControlList_whenUserCantRead_throws() {
    final List<PermissionEntry> expectedPermissionEntries = newArrayList();
    when(permissionDataService.getPermissions(expectedCredential))
      .thenReturn(expectedPermissionEntries);
    final List<PermissionEntry> foundPermissionEntries = subject.getPermissions(expectedCredentialVersion);

    assertThat(foundPermissionEntries, equalTo(expectedPermissionEntries));
  }

  @Test
  public void findPermissionByPathAndActor_whenGivenPathAndActor_returnsPermissionData() {
    when(permissionCheckingService.hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ_ACL))
      .thenReturn(true);

    final String actor = "some-actor";

    final PermissionData expectedPermissionData = new PermissionData(CREDENTIAL_NAME, actor);

    when(permissionDataService.findByPathAndActor(CREDENTIAL_NAME, actor))
      .thenReturn(expectedPermissionData);

    assertThat(subject.findByPathAndActor(CREDENTIAL_NAME, actor), equalTo(expectedPermissionData));
  }

  @Test
  public void findPermissionByNestedPathAndActor_whenAccessedByUserWithREADACL_returnPermissionData() {
    when(permissionCheckingService.hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ_ACL))
      .thenReturn(true);

    final String actor = "some-actor";
    final String path = CREDENTIAL_NAME + "/foo";

    final PermissionData expectedPermissionData = new PermissionData(path, actor);

    when(permissionDataService.findByPathAndActor(path, actor))
      .thenReturn(expectedPermissionData);

    assertThat(subject.findByPathAndActor(path, actor), equalTo(expectedPermissionData));

  }

  @Test
  public void findPermissionByPathAndActor_whenAccessedByAUserWithoutREADACL_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ_ACL))
      .thenReturn(false);

    final String actor = "some-actor";

    assertThatThrownBy(() -> {
      subject.findByPathAndActor(CREDENTIAL_NAME, actor);
    }).isInstanceOf(EntryNotFoundException.class);
  }

  @Test
  public void getAccessControlList_delegatesToDataService() {
    when(permissionCheckingService.hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ_ACL))
      .thenReturn(false);
    final List<PermissionEntry> expectedPermissionEntries = newArrayList();
    when(permissionDataService.getPermissions(expectedCredential))
      .thenReturn(expectedPermissionEntries);

    try {
      subject.getPermissions(expectedCredentialVersion);
      fail();
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void deleteAccessControlEntry_whenTheUserHasPermission_delegatesToDataService() {
    when(permissionCheckingService.hasPermission(userContext.getActor(), CREDENTIAL_NAME, PermissionOperation.WRITE_ACL))
      .thenReturn(true);
    when(permissionCheckingService.userAllowedToOperateOnActor("other-actor"))
      .thenReturn(true);
    when(permissionDataService.deletePermissions(CREDENTIAL_NAME, "other-actor"))
      .thenReturn(true);
    final boolean result = subject.deletePermissions(CREDENTIAL_NAME, "other-actor");

    assertThat(result, equalTo(true));
  }

  @Test
  public void deleteAccessControlEntry_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(userContext.getActor(), CREDENTIAL_NAME, PermissionOperation.WRITE_ACL))
      .thenReturn(false);
    when(permissionDataService.deletePermissions(CREDENTIAL_NAME, "other-actor"))
      .thenReturn(true);
    try {
      subject.deletePermissions(CREDENTIAL_NAME, "other-actor");
      fail("should throw");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void deleteAccessControlEntry_whenTheUserIsTheSameAsActor_throwsAnException() {
    when(permissionCheckingService.hasPermission(userContext.getActor(), CREDENTIAL_NAME, PermissionOperation.WRITE_ACL))
      .thenReturn(true);
    when(permissionDataService.deletePermissions(CREDENTIAL_NAME, userContext.getActor()))
      .thenReturn(true);
    try {
      subject.deletePermissions(CREDENTIAL_NAME, userContext.getActor());
      fail("should throw");
    } catch (final InvalidPermissionOperationException iaoe) {
      assertThat(iaoe.getMessage(), IsEqual.equalTo(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION));
    }
  }
}

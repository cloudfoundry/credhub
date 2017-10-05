package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialNameDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.PermissionsView;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class PermissionsHandlerTest {
  private static final String CREDENTIAL_NAME = "/test-credential";
  private static final String ACTOR_NAME = "test-actor";
  private static final String ACTOR_NAME2 = "someone-else";
  private static final String USER = "test-user";

  private PermissionsHandler subject;

  private PermissionService permissionService;
  private CredentialNameDataService credentialNameDataService;

  private final CredentialName credentialName = new CredentialName(CREDENTIAL_NAME);
  private final UserContext userContext = mock(UserContext.class);

  @Before
  public void beforeEach() {
    permissionService = mock(PermissionService.class);
    credentialNameDataService = mock(CredentialNameDataService.class);
    subject = new PermissionsHandler(
        permissionService,
        credentialNameDataService
    );

    when(credentialNameDataService.findOrThrow(any(String.class))).thenReturn(credentialName);
  }

  @Test
  public void getPermissions_whenTheNameDoesntStartWithASlash_fixesTheName() {
    List<PermissionEntry> accessControlList = newArrayList();
    when(permissionService.getAccessControlList(any(CredentialName.class)))
        .thenReturn(accessControlList);
    when(permissionService.hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(READ_ACL)))
        .thenReturn(true);
    when(credentialNameDataService.findOrThrow(any(String.class)))
        .thenReturn(new CredentialName(CREDENTIAL_NAME));

    PermissionsView response = subject.getPermissions(
        CREDENTIAL_NAME,
        userContext
    );
    assertThat(response.getCredentialName(), equalTo(CREDENTIAL_NAME));
  }

  @Test
  public void getPermissions_verifiesTheUserHasPermissionToReadTheAcl_andReturnsTheAclResponse() {
    ArrayList<PermissionOperation> operations = newArrayList(
        READ,
        WRITE
    );
    when(permissionService.hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(READ_ACL)))
        .thenReturn(true);
    PermissionEntry permissionEntry = new PermissionEntry(
        ACTOR_NAME,
        operations
    );
    List<PermissionEntry> accessControlList = newArrayList(permissionEntry);
    when(permissionService.getAccessControlList(credentialName))
        .thenReturn(accessControlList);

    PermissionsView response = subject.getPermissions(
        CREDENTIAL_NAME,
        userContext
    );

    verify(permissionService, times(1))
        .hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(READ_ACL));

    List<PermissionEntry> accessControlEntries = response.getPermissions();

    assertThat(response.getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(accessControlEntries, hasSize(1));

    PermissionEntry entry = accessControlEntries.get(0);
    assertThat(entry.getActor(), equalTo(ACTOR_NAME));

    List<PermissionOperation> allowedOperations = entry.getAllowedOperations();
    assertThat(allowedOperations, contains(
        equalTo(READ),
        equalTo(WRITE)
    ));
  }

  @Test
  public void setPermissions_setsAndReturnsThePermissions() {
    when(permissionService.hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(WRITE_ACL)))
        .thenReturn(true);
    when(permissionService.userAllowedToOperateOnActor(userContext, ACTOR_NAME))
        .thenReturn(true);

    ArrayList<PermissionOperation> operations = newArrayList(
        READ,
        WRITE
    );
    PermissionEntry permissionEntry = new PermissionEntry(ACTOR_NAME, operations);
    List<PermissionEntry> accessControlList = newArrayList(permissionEntry);

    PermissionEntry preexistingPermissionEntry = new PermissionEntry(
        ACTOR_NAME2,
        newArrayList(READ)
    );
    List<PermissionEntry> expectedControlList = newArrayList(permissionEntry,
        preexistingPermissionEntry);

    when(permissionService.getAccessControlList(credentialName))
        .thenReturn(expectedControlList);

    when(credentialNameDataService.find(CREDENTIAL_NAME))
        .thenReturn(credentialName);

    PermissionsView response = subject.setPermissions(CREDENTIAL_NAME, userContext, accessControlList);

    List<PermissionEntry> accessControlEntries = response.getPermissions();

    assertThat(response.getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(accessControlEntries, hasSize(2));

    PermissionEntry entry1 = accessControlEntries.get(0);
    assertThat(entry1.getActor(), equalTo(ACTOR_NAME));
    assertThat(entry1.getAllowedOperations(), contains(
        equalTo(READ),
        equalTo(WRITE)
    ));

    PermissionEntry entry2 = accessControlEntries.get(1);
    assertThat(entry2.getActor(), equalTo(ACTOR_NAME2));
    assertThat(entry2.getAllowedOperations(), contains(equalTo(READ)));
  }

  @Test
  public void setPermissions_whenUserDoesNotHavePermission_throwsException() {
    when(permissionService.hasPermission(USER, CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(false);
    when(permissionService.userAllowedToOperateOnActor(userContext, ACTOR_NAME))
        .thenReturn(true);
    when(credentialNameDataService.find(CREDENTIAL_NAME))
        .thenReturn(credentialName);

    try {
      subject.setPermissions(CREDENTIAL_NAME, userContext, emptyList());
      fail("should throw");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
      verify(permissionService, times(0)).saveAccessControlEntries(any(), any());
    }
  }

  @Test
  public void setPermissions_whenUserUpdatesOwnPermission_throwsException() {
    when(permissionService.hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(WRITE_ACL)))
        .thenReturn(true);
    when(credentialNameDataService.find(CREDENTIAL_NAME))
        .thenReturn(credentialName);
    when(permissionService.userAllowedToOperateOnActor(userContext, ACTOR_NAME))
        .thenReturn(false);

    try {
      subject.setPermissions(CREDENTIAL_NAME, userContext, Arrays.asList(
          new PermissionEntry(ACTOR_NAME, Arrays.asList(READ)))
      );
    } catch (InvalidAclOperationException e) {
      assertThat(e.getMessage(), equalTo("error.acl.invalid_update_operation"));
      verify(permissionService, times(0)).saveAccessControlEntries(any(), any());
    }
  }

  @Test
  public void setPermissions_whenTheCredentialDoesNotExist_throwsException() {
    when(permissionService.hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(WRITE_ACL)))
        .thenReturn(true);
    when(permissionService.userAllowedToOperateOnActor(userContext, ACTOR_NAME))
        .thenReturn(true);
    when(credentialNameDataService.find(CREDENTIAL_NAME))
        .thenReturn(null);

    try {
      subject.setPermissions(CREDENTIAL_NAME, userContext, emptyList());
      fail("should throw");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
      verify(permissionService, times(0)).saveAccessControlEntries(any(), any());
    }
  }

  @Test
  public void deletePermissions_whenTheUserHasPermission_deletesTheAce() {
    when(permissionService.hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(WRITE_ACL)))
        .thenReturn(true);
    when(permissionService.deleteAccessControlEntry(CREDENTIAL_NAME, ACTOR_NAME))
        .thenReturn(true);
    when(permissionService.userAllowedToOperateOnActor(userContext, ACTOR_NAME))
        .thenReturn(true);

    subject.deletePermissionEntry(userContext, CREDENTIAL_NAME, ACTOR_NAME
    );

    verify(permissionService, times(1)).deleteAccessControlEntry(
        CREDENTIAL_NAME, ACTOR_NAME);
  }

  @Test
  public void deletePermissions_whenTheUserDeletesOwnPermission_throwsAnException() {
    when(permissionService.hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(WRITE_ACL)))
        .thenReturn(true);
    when(permissionService.userAllowedToOperateOnActor(userContext, ACTOR_NAME))
        .thenReturn(false);

    try {
      subject.deletePermissionEntry(userContext, CREDENTIAL_NAME, ACTOR_NAME
      );
    } catch( InvalidAclOperationException iaoe ){
      assertThat(iaoe.getMessage(), equalTo("error.acl.invalid_update_operation"));
    }
  }

  @Test
  public void deletePermissions_whenNothingIsDeleted_throwsAnException() {
    when(permissionService.hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(WRITE_ACL)))
        .thenReturn(true);
    when(permissionService.userAllowedToOperateOnActor(userContext, ACTOR_NAME))
        .thenReturn(true);
    when(permissionService.deleteAccessControlEntry(CREDENTIAL_NAME, ACTOR_NAME))
        .thenReturn(false);

    try {
      subject.deletePermissionEntry(userContext, CREDENTIAL_NAME, ACTOR_NAME
      );
      fail("should throw");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void deletePermissions_whenTheUserLacksPermission_throwsInsteadOfDeletingThePermissions() {
    when(permissionService.hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(WRITE_ACL)))
        .thenReturn(false);
    when(permissionService.userAllowedToOperateOnActor(userContext, ACTOR_NAME))
        .thenReturn(true);

    try {
      subject.deletePermissionEntry(userContext, CREDENTIAL_NAME, ACTOR_NAME
      );
      fail("should throw");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
      verify(permissionService, times(0)).deleteAccessControlEntry(any(), any());
    }
  }
}

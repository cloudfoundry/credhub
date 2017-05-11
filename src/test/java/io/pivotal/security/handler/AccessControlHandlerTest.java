package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.data.CredentialNameDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.AccessControlListResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class AccessControlHandlerTest {
  private static final String CREDENTIAL_NAME = "/test-credential";
  private static final String ACTOR_NAME = "test-actor";
  private static final String ACTOR_NAME2 = "someone-else";

  private AccessControlHandler subject;

  private PermissionService permissionService;
  private AccessControlDataService accessControlDataService;
  private CredentialNameDataService credentialNameDataService;

  private final CredentialName credentialName = new CredentialName(CREDENTIAL_NAME);
  private final UserContext userContext = mock(UserContext.class);

  @Before
  public void beforeEach() {
    permissionService = mock(PermissionService.class);
    accessControlDataService = mock(AccessControlDataService.class);
    credentialNameDataService = mock(CredentialNameDataService.class);
    subject = new AccessControlHandler(
        permissionService,
        accessControlDataService,
        credentialNameDataService
    );

    when(credentialNameDataService.findOrThrow(any(String.class))).thenReturn(credentialName);
  }

  @Test
  public void getAccessControlListResponse_whenTheNameDoesntStartWithASlash_fixesTheName() {
    List<AccessControlEntry> accessControlList = newArrayList();
    when(accessControlDataService.getAccessControlList(any(CredentialName.class)))
        .thenReturn(accessControlList);
    when(credentialNameDataService.findOrThrow(any(String.class)))
        .thenReturn(new CredentialName(CREDENTIAL_NAME));

    AccessControlListResponse response = subject.getAccessControlListResponse(
        null,
        CREDENTIAL_NAME
    );
    assertThat(response.getCredentialName(), equalTo(CREDENTIAL_NAME));
  }

  @Test
  public void getAccessControlListResponse_verifiesTheUserHasPermissionToReadTheAcl_andReturnsTheAclResponse() {
    ArrayList<AccessControlOperation> operations = newArrayList(
        AccessControlOperation.READ,
        AccessControlOperation.WRITE
    );
    AccessControlEntry accessControlEntry = new AccessControlEntry(
        ACTOR_NAME,
        operations
    );
    List<AccessControlEntry> accessControlList = newArrayList(accessControlEntry);
    when(accessControlDataService.getAccessControlList(credentialName))
        .thenReturn(accessControlList);

    AccessControlListResponse response = subject.getAccessControlListResponse(
        userContext,
        CREDENTIAL_NAME
    );

    verify(permissionService, times(1))
        .verifyAclReadPermission(userContext, CREDENTIAL_NAME);

    List<AccessControlEntry> accessControlEntries = response.getAccessControlList();

    assertThat(response.getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(accessControlEntries, hasSize(1));

    AccessControlEntry entry = accessControlEntries.get(0);
    assertThat(entry.getActor(), equalTo(ACTOR_NAME));

    List<AccessControlOperation> allowedOperations = entry.getAllowedOperations();
    assertThat(allowedOperations, contains(
        equalTo(AccessControlOperation.READ),
        equalTo(AccessControlOperation.WRITE)
    ));
  }

  @Test
  public void setAccessControlEntries_setsAndReturnsTheAces() {
    when(permissionService.hasAclWritePermission(userContext, CREDENTIAL_NAME))
        .thenReturn(true);

    ArrayList<AccessControlOperation> operations = newArrayList(
        AccessControlOperation.READ,
        AccessControlOperation.WRITE
    );
    AccessControlEntry accessControlEntry = new AccessControlEntry(ACTOR_NAME, operations);
    List<AccessControlEntry> accessControlList = newArrayList(accessControlEntry);

    AccessControlEntry preexistingAccessControlEntry = new AccessControlEntry(
        ACTOR_NAME2,
        newArrayList(AccessControlOperation.READ)
    );
    List<AccessControlEntry> expectedControlList = newArrayList(accessControlEntry, preexistingAccessControlEntry);

    when(accessControlDataService.getAccessControlList(credentialName))
        .thenReturn(expectedControlList);

    AccessControlListResponse response = subject.setAccessControlEntries(userContext, CREDENTIAL_NAME, accessControlList);

    List<AccessControlEntry> accessControlEntries = response.getAccessControlList();

    assertThat(response.getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(accessControlEntries, hasSize(2));

    AccessControlEntry entry1 = accessControlEntries.get(0);
    assertThat(entry1.getActor(), equalTo(ACTOR_NAME));
    assertThat(entry1.getAllowedOperations(), contains(
        equalTo(AccessControlOperation.READ),
        equalTo(AccessControlOperation.WRITE)
    ));

    AccessControlEntry entry2 = accessControlEntries.get(1);
    assertThat(entry2.getActor(), equalTo(ACTOR_NAME2));
    assertThat(entry2.getAllowedOperations(), contains(equalTo(AccessControlOperation.READ)));
  }

  @Test
  public void setAccessControlEntries_whenUserDoesNotHavePermission_throwsException() {
    when(permissionService.hasAclWritePermission(userContext, CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.setAccessControlEntries(userContext, CREDENTIAL_NAME, emptyList());
      fail("should throw");
    } catch (PermissionException e) {
      assertThat(e.getMessage(), equalTo("error.acl.lacks_credential_write"));
      verify(accessControlDataService, times(0)).saveAccessControlEntries(any(), any());
    }
  }

  @Test
  public void deleteAccessControlEntries_whenTheUserHasPermission_deletesTheAce() {
    when(credentialNameDataService.findOrThrow(CREDENTIAL_NAME)).thenReturn(credentialName);
    when(permissionService.hasAclWritePermission(userContext, CREDENTIAL_NAME))
        .thenReturn(true);

    subject.deleteAccessControlEntry( userContext, CREDENTIAL_NAME, ACTOR_NAME);

    verify(accessControlDataService, times(1)).deleteAccessControlEntry(
        CREDENTIAL_NAME, ACTOR_NAME);
  }

  @Test
  public void deleteAccessControlEntries_whenTheUserLacksPermission_throwsInsteadOfDeletingThePermissions() {
    when(permissionService.hasAclWritePermission(userContext, CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.deleteAccessControlEntry(userContext, CREDENTIAL_NAME, ACTOR_NAME);
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.acl.lacks_credential_write"));
      verify(accessControlDataService, times(0)).deleteAccessControlEntry(any(), any());
    }
  }
}

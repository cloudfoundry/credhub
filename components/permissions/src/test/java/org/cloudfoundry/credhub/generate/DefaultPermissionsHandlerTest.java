package org.cloudfoundry.credhub.generate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.google.common.collect.Lists;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.data.CredentialDataService;
import org.cloudfoundry.credhub.data.PermissionData;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException;
import org.cloudfoundry.credhub.requests.PermissionEntry;
import org.cloudfoundry.credhub.requests.PermissionsRequest;
import org.cloudfoundry.credhub.requests.PermissionsV2Request;
import org.cloudfoundry.credhub.services.DefaultPermissionedCredentialService;
import org.cloudfoundry.credhub.services.PermissionCheckingService;
import org.cloudfoundry.credhub.services.PermissionService;
import org.cloudfoundry.credhub.views.PermissionsV2View;
import org.cloudfoundry.credhub.views.PermissionsView;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Collections.emptyList;
import static org.cloudfoundry.credhub.generate.DefaultPermissionsHandler.INVALID_NUMBER_OF_PERMISSIONS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class DefaultPermissionsHandlerTest {
  private static final String CREDENTIAL_NAME = "/test-credential";
  private static final String ACTOR_NAME = "test-actor";
  private static final String ACTOR_NAME2 = "someone-else";
  private static final String USER = "test-user";
  private final Credential credential = new Credential(CREDENTIAL_NAME);
  private final CredentialVersion credentialVersion = new PasswordCredentialVersion(new PasswordCredentialVersionData(CREDENTIAL_NAME));
  private DefaultPermissionsHandler subject;
  private PermissionService permissionService;
  private PermissionCheckingService permissionCheckingService;
  private CredentialDataService credentialDataService;
  private DefaultPermissionedCredentialService permissionedCredentialService;
  private PermissionsRequest permissionsRequest;
  private PermissionsV2Request permissionsV2Request;

  @Before
  public void beforeEach() {
    permissionService = mock(PermissionService.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    credentialDataService = mock(CredentialDataService.class);
    permissionedCredentialService = mock(DefaultPermissionedCredentialService.class);
    subject = new DefaultPermissionsHandler(
      permissionService,
      permissionedCredentialService
    );

    permissionsRequest = mock(PermissionsRequest.class);
    permissionsV2Request = new PermissionsV2Request();

    when(permissionedCredentialService.findMostRecent(CREDENTIAL_NAME)).thenReturn(credentialVersion);
    when(credentialDataService.find(any(String.class))).thenReturn(credential);
  }

  @Test
  public void findByPathAndActor_whenGivenAPathAndActor_returnsPermissionsV2View() {
    final String path = "some-path";
    final String actor = "some-actor";

    final PermissionsV2View expectedPermissionsV2View = new PermissionsV2View(
      path,
      emptyList(),
      actor,
      null
    );

    when(permissionService.findByPathAndActor(path, actor))
      .thenReturn(new PermissionData(path, actor));

    final PermissionsV2View actualPermissionsV2View = subject.findByPathAndActor(path, actor);
    assertThat(
      actualPermissionsV2View,
      equalTo(expectedPermissionsV2View)
    );
  }

  @Test
  public void getPermissions_whenTheNameDoesntStartWithASlash_fixesTheName() {
    final List<PermissionEntry> accessControlList = newArrayList();
    when(permissionService.getPermissions(any(CredentialVersion.class)))
      .thenReturn(accessControlList);
    when(permissionCheckingService
      .hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(PermissionOperation.READ_ACL)))
      .thenReturn(true);

    final PermissionsView response = subject.getPermissions(CREDENTIAL_NAME);
    assertThat(response.getCredentialName(), equalTo(CREDENTIAL_NAME));

  }

  @Test
  public void getPermissions_verifiesTheUserHasPermissionToReadTheAcl_andReturnsTheAclResponse() {
    final List<PermissionOperation> operations = newArrayList(
      PermissionOperation.READ,
      PermissionOperation.WRITE
    );
    when(permissionCheckingService
      .hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(PermissionOperation.READ_ACL)))
      .thenReturn(true);
    final PermissionEntry permissionEntry = new PermissionEntry(
      ACTOR_NAME,
      "test-path",
      operations
    );
    final List<PermissionEntry> accessControlList = newArrayList(permissionEntry);
    when(permissionService.getPermissions(credentialVersion))
      .thenReturn(accessControlList);

    final PermissionsView response = subject.getPermissions(
      CREDENTIAL_NAME
    );

    final List<PermissionEntry> accessControlEntries = response.getPermissions();

    assertThat(response.getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(accessControlEntries, hasSize(1));

    final PermissionEntry entry = accessControlEntries.get(0);

    assertThat(entry.getActor(), equalTo(ACTOR_NAME));

    final List<PermissionOperation> allowedOperations = entry.getAllowedOperations();
    assertThat(allowedOperations, contains(
      equalTo(PermissionOperation.READ),
      equalTo(PermissionOperation.WRITE)
    ));
  }

  @Test
  public void setPermissions_setsAndReturnsThePermissions() {
    when(permissionCheckingService
      .hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(PermissionOperation.WRITE_ACL)))
      .thenReturn(true);
    when(permissionCheckingService
      .userAllowedToOperateOnActor(ACTOR_NAME))
      .thenReturn(true);

    final List<PermissionOperation> operations = newArrayList(
      PermissionOperation.READ,
      PermissionOperation.WRITE
    );
    final PermissionEntry permissionEntry = new PermissionEntry(ACTOR_NAME, "test-path", operations);
    final List<PermissionEntry> accessControlList = newArrayList(permissionEntry);

    final PermissionEntry preexistingPermissionEntry = new PermissionEntry(ACTOR_NAME2, "test-path", Lists.newArrayList(PermissionOperation.READ)
    );
    final List<PermissionEntry> expectedControlList = newArrayList(permissionEntry,
      preexistingPermissionEntry);

    when(permissionService.getPermissions(credentialVersion))
      .thenReturn(expectedControlList);

    when(permissionsRequest.getCredentialName()).thenReturn(CREDENTIAL_NAME);
    when(permissionsRequest.getPermissions()).thenReturn(accessControlList);

    subject.writePermissions(permissionsRequest);

    final ArgumentCaptor<List> permissionsListCaptor = ArgumentCaptor.forClass(List.class);
    verify(permissionService).savePermissionsForUser(permissionsListCaptor.capture());

    final PermissionEntry entry = accessControlList.get(0);
    assertThat(entry.getActor(), equalTo(ACTOR_NAME));
    assertThat(entry.getPath(), equalTo(CREDENTIAL_NAME));
    assertThat(entry.getAllowedOperations(), contains(equalTo(PermissionOperation.READ), equalTo(PermissionOperation.WRITE)));
  }

  @Test(expected = IllegalArgumentException.class)
  public void setPermissionsCalledWithOnePermission_whenPermissionServiceReturnsMultiplePermissions_throwsException() {
    when(permissionCheckingService.hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(PermissionOperation.WRITE_ACL))).thenReturn(true);
    when(permissionCheckingService.userAllowedToOperateOnActor(ACTOR_NAME)).thenReturn(true);

    final List<PermissionData> permissionList = new ArrayList<>();
    permissionList.add(new PermissionData());
    permissionList.add(new PermissionData());

    when(permissionService.savePermissionsForUser(any())).thenReturn(permissionList);

    final List<PermissionOperation> operations = newArrayList(PermissionOperation.READ, PermissionOperation.WRITE);
    final PermissionEntry permissionEntry = new PermissionEntry(ACTOR_NAME, "test-path", operations);

    final PermissionEntry preexistingPermissionEntry = new PermissionEntry(ACTOR_NAME2, "test-path", Lists.newArrayList(PermissionOperation.READ));
    final List<PermissionEntry> expectedControlList = newArrayList(permissionEntry, preexistingPermissionEntry);

    when(permissionService.getPermissions(credentialVersion)).thenReturn(expectedControlList);

    permissionsV2Request.setOperations(operations);
    permissionsV2Request.setPath(CREDENTIAL_NAME);

    try {
      subject.writePermissions(permissionsV2Request);
    } catch (final Exception e) {
      assertThat(e.getMessage(), equalTo(INVALID_NUMBER_OF_PERMISSIONS));
      throw e;
    }

  }

  @Test
  public void setPermissions_whenUserUpdatesOwnPermission_throwsException() {
    when(permissionCheckingService
      .hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(PermissionOperation.WRITE_ACL)))
      .thenReturn(true);
    when(permissionCheckingService
      .userAllowedToOperateOnActor(ACTOR_NAME))
      .thenReturn(false);

    final List<PermissionEntry> accessControlList = Arrays.asList(new PermissionEntry(ACTOR_NAME, "test-path", Arrays.asList(
      PermissionOperation.READ)));
    when(permissionsRequest.getCredentialName()).thenReturn(CREDENTIAL_NAME);
    when(permissionsRequest.getPermissions()).thenReturn(accessControlList);

    try {
      subject.writePermissions(permissionsRequest);
    } catch (final InvalidPermissionOperationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION));
      verify(permissionService, times(0)).savePermissionsForUser(any());
    }
  }

  @Test
  public void deletePermissions_whenTheUserHasPermission_deletesTheAce() {
    when(permissionCheckingService
      .hasPermission(any(String.class), eq(CREDENTIAL_NAME), eq(PermissionOperation.WRITE_ACL)))
      .thenReturn(true);
    when(permissionService.deletePermissions(CREDENTIAL_NAME, ACTOR_NAME))
      .thenReturn(true);
    when(permissionCheckingService
      .userAllowedToOperateOnActor(ACTOR_NAME))
      .thenReturn(true);

    subject.deletePermissionEntry(CREDENTIAL_NAME, ACTOR_NAME
    );

    verify(permissionService, times(1)).deletePermissions(
      CREDENTIAL_NAME, ACTOR_NAME);

  }

  @Test
  public void deletePermissions_whenNothingIsDeleted_throwsAnException() {
    when(permissionService.deletePermissions(CREDENTIAL_NAME, ACTOR_NAME))
      .thenReturn(false);

    try {
      subject.deletePermissionEntry(CREDENTIAL_NAME, ACTOR_NAME
      );
      fail("should throw");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }
}

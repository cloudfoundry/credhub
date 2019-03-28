package org.cloudfoundry.credhub.data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.OperationDeviceAction;
import org.cloudfoundry.credhub.audit.Resource;
import org.cloudfoundry.credhub.audit.entities.V2Permission;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.requests.PermissionEntry;
import org.cloudfoundry.credhub.requests.PermissionsV2Request;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Collections.singletonList;
import static junit.framework.TestCase.assertFalse;
import static org.cloudfoundry.credhub.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.PermissionOperation.READ;
import static org.cloudfoundry.credhub.PermissionOperation.READ_ACL;
import static org.cloudfoundry.credhub.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.PermissionOperation.WRITE_ACL;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
@SuppressFBWarnings(
  value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
  justification = "Let's refactor this class into kotlin"
)
public class PermissionDataServiceTest {
  private static final String CREDENTIAL_NAME = "/lightsaber";
  private static final String CREDENTIAL_NAME_DOES_NOT_EXIST = "/this/credential/does/not/exist";

  private static final String LUKE = "Luke";
  private static final String LEIA = "Leia";
  private static final String HAN_SOLO = "HansSolo";
  private static final String DARTH = "Darth";
  private static final String CHEWIE = "Chewie";
  private static final String NO_ACCESS_CREDENTIAL_NAME = "Alderaan";

  @Autowired
  private PermissionDataService subject;

  @Autowired
  private CredentialDataService credentialDataService;

  @Autowired
  private CEFAuditRecord auditRecord;

  private List<PermissionEntry> aces;
  private Credential credential;

  @Before
  public void beforeEach() {
    seedDatabase();
  }

  @Test
  public void getAccessControlList_givenExistingCredentialName_returnsAcl() {
    final List<PermissionEntry> accessControlEntries = subject.getPermissions(credential);

    assertThat(accessControlEntries, hasSize(3));

    assertThat(accessControlEntries, containsInAnyOrder(
      allOf(hasProperty("actor", equalTo(LUKE)),
        hasProperty("allowedOperations", hasItems(WRITE))),
      allOf(hasProperty("actor", equalTo(LEIA)),
        hasProperty("allowedOperations", hasItems(READ))),
      allOf(hasProperty("actor", equalTo(HAN_SOLO)),
        hasProperty("allowedOperations",
          hasItems(READ_ACL))))
    );
  }

  @Test
  public void findByPathAndActor_givenAnActorAndPath_returnsPermissionData() {
    final PermissionData actualPermission = subject.findByPathAndActor(CREDENTIAL_NAME, LUKE);
    final PermissionData expectedPermission = new PermissionData(CREDENTIAL_NAME, LUKE, newArrayList(WRITE, DELETE));
    expectedPermission.setUuid(actualPermission.getUuid());

    assertThat(
      actualPermission,
      equalTo(expectedPermission)
    );
  }

  @Test
  public void getAllowedOperations_whenTheCredentialExists_andTheActorHasPermissions_returnsListOfActivePermissions() {
    assertThat(subject.getAllowedOperations(CREDENTIAL_NAME, LUKE), containsInAnyOrder(
      WRITE,
      DELETE
    ));
  }

  @Test
  public void getAllowedOperations_whenTheCredentialExists_andTheActorHasNoPermissions_returnsEmptyList() {
    assertThat(subject.getAllowedOperations(CREDENTIAL_NAME, DARTH).size(), equalTo(0));
  }

  @Test
  public void getAllowedOperations_whenTheCredentialDoesNotExist_returnsEmptyList() {
    assertThat(subject.getAllowedOperations("/unicorn", LEIA).size(), equalTo(0));
  }

  @Test
  public void getAccessControlList_whenGivenNonExistentCredentialName_throwsException() {
    try {
      subject.getPermissions(new Credential(CREDENTIAL_NAME_DOES_NOT_EXIST));
    } catch (final EntryNotFoundException enfe) {
      assertThat(enfe.getMessage(), Matchers.equalTo(ErrorMessages.RESOURCE_NOT_FOUND));
    }
  }

  @Test
  public void setAccessControlEntries_whenGivenAnExistingAce_returnsTheAcl() {
    aces = singletonList(
      new PermissionEntry(LUKE, CREDENTIAL_NAME, singletonList(READ))
    );

    subject.savePermissionsWithLogging(aces);

    final List<PermissionEntry> response = subject.getPermissions(credential);

    assertThat(response, containsInAnyOrder(
      allOf(hasProperty("actor", equalTo(LUKE)),
        hasProperty("allowedOperations",
          hasItems(READ, WRITE))),
      allOf(hasProperty("actor", equalTo(LEIA)),
        hasProperty("allowedOperations", hasItems(READ))),
      allOf(hasProperty("actor", equalTo(HAN_SOLO)),
        hasProperty("allowedOperations",
          hasItems(READ_ACL)))));
  }

  @Test
  public void setAccessControlEntries_whenGivenANewAce_returnsTheAcl() {
    final ValueCredentialVersionData valueCredentialData2 = new ValueCredentialVersionData("lightsaber2");
    final Credential credential2 = valueCredentialData2.getCredential();

    credentialDataService.save(credential2);
    aces = singletonList(
      new PermissionEntry(LUKE, credential2.getName(), singletonList(READ)));

    subject.savePermissionsWithLogging(aces);

    final List<PermissionEntry> response = subject.getPermissions(credential2);


    final PermissionEntry permissionEntry = response.get(0);

    assertThat(response, hasSize(1));
    assertThat(permissionEntry.getActor(), equalTo(LUKE));
    assertThat(permissionEntry.getAllowedOperations(), hasSize(1));
    assertThat(permissionEntry.getAllowedOperations(), hasItem(READ));
  }

  @Test
  public void deleteAccessControlEntry_whenGivenExistingCredentialAndActor_deletesTheAce() {
    subject.deletePermissions(CREDENTIAL_NAME, LUKE);

    final List<PermissionEntry> accessControlList = subject
      .getPermissions(credential);

    assertThat(accessControlList, hasSize(2));

    assertThat(accessControlList,
      not(contains(hasProperty("actor", equalTo(LUKE)))));
  }

  @Test
  public void deleteAccessControlEntry_whenNonExistentResource_returnsFalse() {
    final boolean deleted = subject.deletePermissions("/some-thing-that-is-not-here", LUKE);
    assertFalse(deleted);
  }

  @Test
  public void deleteAccessControlEntry_whenNonExistentAce_returnsFalse() {
    final boolean deleted = subject.deletePermissions(CREDENTIAL_NAME, DARTH);
    assertFalse(deleted);
  }

  @Test
  public void deletePermissions_addsToAuditRecord() {
    subject.deletePermissions(CREDENTIAL_NAME, LUKE);
    assertThat(auditRecord.getResourceName(), is(CREDENTIAL_NAME));
  }

  @Test
  public void patchPermissions_addsToAuditRecord() {
    final List<PermissionOperation> operations = new ArrayList<>();
    final String pathName = randomCredentialPath();
    operations.add(PermissionOperation.READ);

    final PermissionsV2Request permission = new PermissionsV2Request();
    permission.setPath(pathName);
    permission.setActor(LUKE);
    permission.setOperations(operations);

    final PermissionData permissionData = subject.saveV2Permissions(permission);
    assertThat(permissionData.getUuid(), notNullValue());

    final List<PermissionOperation> newOperations = new ArrayList<>();
    newOperations.add(PermissionOperation.WRITE);

    subject.patchPermissions(permissionData.getUuid().toString(), newOperations);

    assertThat(auditRecord.getResourceUUID(), is(permissionData.getUuid().toString()));
    final V2Permission requestDetails = (V2Permission) auditRecord.getRequestDetails();
    assertThat(requestDetails.getOperations(), containsInAnyOrder(PermissionOperation.WRITE));
    assertThat(requestDetails.operation(), is(OperationDeviceAction.PATCH_PERMISSIONS));
  }

  @Test
  public void putPermissions_addsToAuditRecord() {
    final PermissionsV2Request request = new PermissionsV2Request();

    final List<PermissionEntry> permissions = new ArrayList<>();
    final List<PermissionOperation> operations = new ArrayList<>();
    operations.add(PermissionOperation.READ);

    final PermissionEntry permissionEntry = new PermissionEntry();
    permissionEntry.setPath(CREDENTIAL_NAME);
    permissionEntry.setActor(LUKE);
    permissionEntry.setAllowedOperations(operations);

    permissions.add(permissionEntry);

    final PermissionData permissionData = subject.savePermissionsWithLogging(permissions).get(0);

    final List<PermissionOperation> newOperations = new ArrayList<>();
    newOperations.add(PermissionOperation.WRITE);

    request.setPath(CREDENTIAL_NAME);
    request.setActor(LUKE);
    request.setOperations(newOperations);

    subject.putPermissions(permissionData.getUuid().toString(), request);

    assertThat(auditRecord.getResourceName(), is(CREDENTIAL_NAME));
    final V2Permission requestDetails = (V2Permission) auditRecord.getRequestDetails();
    assertThat(requestDetails.getPath(), is(CREDENTIAL_NAME));
    assertThat(requestDetails.getActor(), is(LUKE));
    assertThat(requestDetails.getOperations(), contains(PermissionOperation.WRITE));
    assertThat(requestDetails.operation(), is(OperationDeviceAction.PUT_PERMISSIONS));

  }

  @Test
  public void savePermissions_addsToAuditRecord() {
    final List<PermissionEntry> permissions = new ArrayList<>();
    final List<PermissionOperation> operations = new ArrayList<>();
    operations.add(PermissionOperation.READ);

    final PermissionEntry permissionEntry = new PermissionEntry();
    permissionEntry.setPath(CREDENTIAL_NAME);
    permissionEntry.setActor(LUKE);
    permissionEntry.setAllowedOperations(operations);

    permissions.add(permissionEntry);

    subject.savePermissionsWithLogging(permissions);

    final List<Resource> resources = auditRecord.getResourceList();

    assertThat(resources.get(resources.size() - 1).getResourceName(), is(CREDENTIAL_NAME));
    final V2Permission requestDetails = (V2Permission) auditRecord.getRequestDetails();
    assertThat(requestDetails.getPath(), is(CREDENTIAL_NAME));
    assertThat(requestDetails.getActor(), is(LUKE));
  }

  @Test
  public void saveV2Permissions_addsToAuditRecord() {
    final String path = randomCredentialPath();
    final PermissionsV2Request permission = new PermissionsV2Request();
    final List<PermissionOperation> operations = new ArrayList<>();
    operations.add(PermissionOperation.READ);

    permission.setPath(path);
    permission.setActor(LUKE);
    permission.setOperations(operations);

    subject.saveV2Permissions(permission);

    assertThat(auditRecord.getResourceName(), is(path));
    final V2Permission requestDetails = (V2Permission) auditRecord.getRequestDetails();
    assertThat(requestDetails.getPath(), is(path));
    assertThat(requestDetails.getActor(), is(LUKE));
    assertThat(requestDetails.operation(), is(OperationDeviceAction.ADD_PERMISSIONS));

  }

  @Test
  public void deleteV2Permissions_addsToAuditRecord() {
    final PermissionsV2Request request = new PermissionsV2Request();

    final List<PermissionOperation> operations = Collections.singletonList(PermissionOperation.READ);

    final String credentialName = randomCredentialPath();
    request.setPath(credentialName);
    request.setActor(LUKE);
    request.setOperations(operations);

    final PermissionData permissionData = subject.saveV2Permissions(request);

    subject.deletePermissions(permissionData.getUuid());

    assertThat(auditRecord.getResourceName(), is(credentialName));
    final V2Permission requestDetails = (V2Permission) auditRecord.getRequestDetails();
    assertThat(requestDetails.getPath(), is(credentialName));
    assertThat(requestDetails.getActor(), is(LUKE));
    assertThat(requestDetails.getOperations(), contains(PermissionOperation.READ));
    assertThat(requestDetails.operation(), is(OperationDeviceAction.DELETE_PERMISSIONS));
  }

  @Test
  public void getPermissionsByUUID_addsToAuditRecord() {
    final UUID guid = subject.savePermissions(singletonList(new PermissionEntry(LUKE, CREDENTIAL_NAME, newArrayList(WRITE, DELETE)))).get(0).getUuid();
    subject.getPermission(guid);
    assertThat(auditRecord.getResourceName(), is(CREDENTIAL_NAME));
  }

  @Test
  public void hasAclReadPermission_whenActorHasAclRead_returnsTrue() {
    assertThat(subject.hasPermission(HAN_SOLO, CREDENTIAL_NAME, READ_ACL),
      is(true));
  }

  @Test
  public void hasAclReadPermission_whenActorHasReadButNotReadAcl_returnsFalse() {
    assertThat(subject.hasPermission(LUKE, CREDENTIAL_NAME, READ),
      is(false));
  }

  @Test
  public void hasAclReadPermission_whenActorHasNoPermissions_returnsFalse() {
    assertThat(subject.hasPermission(CHEWIE, CREDENTIAL_NAME, READ),
      is(false));
  }

  @Test
  public void hasAclReadPermission_whenCredentialDoesNotExist_returnsFalse() {
    assertThat(subject.hasPermission(LUKE, CREDENTIAL_NAME_DOES_NOT_EXIST, READ),
      is(false));
  }

  @Test
  public void hasAclWritePermission_whenActorHasAclWrite_returnsTrue() {
    assertThat(subject.hasPermission(HAN_SOLO, CREDENTIAL_NAME, WRITE_ACL),
      is(true));
  }

  @Test
  public void hasAclWritePermission_whenActorHasWriteButNotWriteAcl_returnsFalse() {
    assertThat(subject.hasPermission(LUKE, CREDENTIAL_NAME, WRITE_ACL),
      is(false));
  }

  @Test
  public void hasAclWritePermission_whenActorHasNoPermissions_returnsFalse() {
    assertThat(subject.hasPermission(CHEWIE, CREDENTIAL_NAME, WRITE_ACL),
      is(false));
  }

  @Test
  public void hasAclWritePermission_whenCredentialDoesNotExist_returnsFalse() {
    assertThat(subject.hasPermission(LUKE, CREDENTIAL_NAME_DOES_NOT_EXIST, WRITE_ACL),
      is(false));
  }

  @Test
  public void hasReadPermission_whenActorHasRead_returnsTrue() {
    assertThat(subject.hasPermission(LEIA, CREDENTIAL_NAME, READ),
      is(true));
  }

  @Test
  public void hasReadPermission_givenNameWithoutLeadingSlashAndHasRead_returnsTrue() {
    assertThat(subject.hasPermission(LEIA, CREDENTIAL_NAME, READ),
      is(true));
  }

  @Test
  public void hasReadPermission_whenActorHasWriteButNotRead_returnsFalse() {
    assertThat(subject.hasPermission(LUKE, CREDENTIAL_NAME, READ),
      is(false));
  }

  @Test
  public void hasReadPermission_whenActorHasNoPermissions_returnsFalse() {
    assertThat(subject.hasPermission(CHEWIE, CREDENTIAL_NAME, READ),
      is(false));
  }

  @Test
  public void hasCredentialWritePermission_whenActorHasWritePermission_returnsTrue() {
    assertThat(subject.hasPermission(LUKE, CREDENTIAL_NAME, WRITE), is(true));
  }

  @Test
  public void hasCredentialWritePermission_whenActorOnlyHasOtherPermissions_returnsFalse() {
    assertThat(subject.hasPermission(LEIA, CREDENTIAL_NAME, WRITE), is(false));
  }

  @Test
  public void hasCredentialWritePermission_whenActorHasNoPermissions_returnsFalse() {
    assertThat(subject.hasPermission(DARTH, CREDENTIAL_NAME, WRITE), is(false));
  }

  @Test
  public void hasCredentialDeletePermission_whenActorHasDeletePermission_returnsTrue() {
    assertThat(subject.hasPermission(LUKE, CREDENTIAL_NAME, DELETE), is(true));
  }

  @Test
  public void hasCredentialDeletePermission_whenActorOnlyHasOtherPermissions_returnsFalse() {
    assertThat(subject.hasPermission(LEIA, CREDENTIAL_NAME, DELETE), is(false));
  }

  @Test
  public void hasCredentialDeletePermission_whenActorHasNoPermissions_returnsFalse() {
    assertThat(subject.hasPermission(DARTH, CREDENTIAL_NAME, DELETE), is(false));
  }

  @Test
  public void hasReadPermission_whenCredentialDoesNotExist_returnsFalse() {
    assertThat(subject.hasPermission(LUKE, CREDENTIAL_NAME_DOES_NOT_EXIST, READ),
      is(false));
  }

  @Test
  public void hasNoPermissions_whenCredentialHasPermissions_returnsFalse() {
    assertThat(subject.hasNoDefinedAccessControl(CREDENTIAL_NAME), is(false));
  }

  @Test
  public void hasNoPermissions_whenCredentialDoesNotExist_returnsFalse() {
    assertThat(subject.hasNoDefinedAccessControl(CREDENTIAL_NAME_DOES_NOT_EXIST), is(false));
  }

  @Test
  public void hasNoPermissions_whenCredentialHasNoPermissions_returnsTrue() {
    assertThat(subject.hasNoDefinedAccessControl(NO_ACCESS_CREDENTIAL_NAME), is(true));
  }

  private void seedDatabase() {
    final ValueCredentialVersionData valueCredentialData = new ValueCredentialVersionData(CREDENTIAL_NAME);
    credential = valueCredentialData.getCredential();
    this.credential = credentialDataService.save(this.credential);

    final ValueCredentialVersionData noAccessValueCredentialData = new ValueCredentialVersionData(NO_ACCESS_CREDENTIAL_NAME);
    final Credential noAccessValueCredential = noAccessValueCredentialData.getCredential();
    credentialDataService.save(noAccessValueCredential);

    subject.savePermissionsWithLogging(singletonList(new PermissionEntry(LUKE, CREDENTIAL_NAME, newArrayList(WRITE, DELETE))));
    subject.savePermissionsWithLogging(singletonList(new PermissionEntry(LEIA, CREDENTIAL_NAME, singletonList(READ))));
    subject.savePermissionsWithLogging(singletonList(new PermissionEntry(HAN_SOLO, CREDENTIAL_NAME, newArrayList(READ_ACL, WRITE_ACL))));
  }

  private String randomCredentialPath() {
    return "/" + RandomStringUtils.randomAlphanumeric(50);
  }
}

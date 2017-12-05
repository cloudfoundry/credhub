package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.apache.commons.lang3.StringUtils;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.credhub.request.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ_ACL;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE_ACL;
import static java.util.Collections.singletonList;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.CoreMatchers.allOf;
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
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class PermissionDataServiceTest {
  private static final String CREDENTIAL_NAME = "/lightsaber";
  private static final String CREDENTIAL_NAME_WITHOUT_LEADING_SLASH = StringUtils.removeStart(CREDENTIAL_NAME, "/");
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
    } catch (EntryNotFoundException enfe) {
      assertThat(enfe.getMessage(), Matchers.equalTo("error.resource_not_found"));
    }
  }

  @Test
  public void setAccessControlEntries_whenGivenAnExistingAce_returnsTheAcl() {
    aces = singletonList(
        new PermissionEntry(LUKE, singletonList(READ))
    );

    subject.savePermissions(credential, aces);

    List<PermissionEntry> response = subject.getPermissions(credential);

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
        new PermissionEntry(LUKE, singletonList(READ)));

    subject.savePermissions(credential2, aces);

    List<PermissionEntry> response = subject.getPermissions(credential2);


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
    boolean deleted = subject.deletePermissions("/some-thing-that-is-not-here", LUKE);
    assertFalse(deleted);
  }

  @Test
  public void deleteAccessControlEntry_whenNonExistentAce_returnsFalse() {
    boolean deleted = subject.deletePermissions(CREDENTIAL_NAME, DARTH);
    assertFalse(deleted);
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
    ValueCredentialVersionData valueCredentialData = new ValueCredentialVersionData(CREDENTIAL_NAME);
    credential = valueCredentialData.getCredential();
    ValueCredentialVersionData noAccessValueCredentialData = new ValueCredentialVersionData(
        NO_ACCESS_CREDENTIAL_NAME);
    Credential noAccessValueCredential = noAccessValueCredentialData.getCredential();

    Credential noAccessCredential = credentialDataService.save(noAccessValueCredential);
    this.credential = credentialDataService.save(this.credential);

    subject.savePermissions(
        this.credential,
        singletonList(new PermissionEntry(LUKE,
            newArrayList(WRITE, DELETE)))
    );

    subject.savePermissions(
        this.credential,
        singletonList(new PermissionEntry(LEIA,
            singletonList(READ)))
    );

    subject.savePermissions(
        this.credential,
        singletonList(new PermissionEntry(HAN_SOLO,
            newArrayList(READ_ACL, WRITE_ACL)))
    );
  }
}

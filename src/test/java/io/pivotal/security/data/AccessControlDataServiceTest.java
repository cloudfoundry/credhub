package io.pivotal.security.data;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.entity.ValueCredentialData;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.util.DatabaseProfileResolver;
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
import static java.util.Collections.singletonList;
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
public class AccessControlDataServiceTest {
  private static final String CREDENTIAL_NAME = "/lightsaber";
  private static final String CREDENTIAL_NAME_DOES_NOT_EXIST = "/this/credential/does/not/exist";

  @Autowired
  private AccessControlDataService subject;

  @Autowired
  private CredentialNameDataService credentialNameDataService;

  private List<AccessControlEntry> aces;
  private CredentialName credentialName;

  @Before
  public void beforeEach() {
    seedDatabase();
  }

  @Test
  public void getAccessControlList_givenExistingCredentialName_returnsAcl() {
    final List<AccessControlEntry> accessControlEntries = subject.getAccessControlList(credentialName);

    assertThat(accessControlEntries, hasSize(3));

    assertThat(accessControlEntries, containsInAnyOrder(
        allOf(hasProperty("actor", equalTo("Luke")),
            hasProperty("allowedOperations", hasItems(AccessControlOperation.WRITE))),
        allOf(hasProperty("actor", equalTo("Leia")),
            hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))),
        allOf(hasProperty("actor", equalTo("HanSolo")),
            hasProperty("allowedOperations",
                hasItems(AccessControlOperation.READ_ACL))))
    );
  }

  @Test
  public void getAccessControlList_whenGivenNonExistentCredentialName_throwsException() {
    try {
      subject.getAccessControlList(new CredentialName("/unicorn"));
    } catch (EntryNotFoundException enfe) {
      assertThat(enfe.getMessage(), Matchers.equalTo("error.resource_not_found"));
    }
  }

  @Test
  public void setAccessControlEntries_whenGivenAnExistingAce_returnsTheAcl() {
    aces = singletonList(
        new AccessControlEntry("Luke", singletonList(AccessControlOperation.READ))
    );

    subject.saveAccessControlEntries(credentialName, aces);

    List<AccessControlEntry> response = subject.getAccessControlList(credentialName);

        assertThat(response, containsInAnyOrder(
        allOf(hasProperty("actor", equalTo("Luke")),
            hasProperty("allowedOperations",
                hasItems(AccessControlOperation.READ, AccessControlOperation.WRITE))),
        allOf(hasProperty("actor", equalTo("Leia")),
            hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))),
        allOf(hasProperty("actor", equalTo("HanSolo")),
            hasProperty("allowedOperations",
                hasItems(AccessControlOperation.READ_ACL)))));
  }

  @Test
  public void setAccessControlEntries_whenGivenANewAce_returnsTheAcl() {
    final ValueCredentialData valueCredentialData2 = new ValueCredentialData("lightsaber2");
    final CredentialName credentialName2 = valueCredentialData2.getCredentialName();

    credentialNameDataService.save(credentialName2);
    aces = singletonList(
        new AccessControlEntry("Luke", singletonList(AccessControlOperation.READ)));

    subject.saveAccessControlEntries(credentialName2, aces);

    List<AccessControlEntry> response = subject.getAccessControlList(credentialName2);


    final AccessControlEntry accessControlEntry = response.get(0);

    assertThat(response, hasSize(1));
    assertThat(accessControlEntry.getActor(), equalTo("Luke"));
    assertThat(accessControlEntry.getAllowedOperations(), hasSize(1));
    assertThat(accessControlEntry.getAllowedOperations(), hasItem(AccessControlOperation.READ));
  }

  @Test
  public void deleteAccessControlEntry_whenGivenExistingCredentialAndActor_deletesTheAcl() {

    subject.deleteAccessControlEntry("Luke", credentialName);

    final List<AccessControlEntry> accessControlList = subject
        .getAccessControlList(credentialName);

    assertThat(accessControlList, hasSize(2));

    assertThat(accessControlList,
        not(contains(hasProperty("actor", equalTo("Luke")))));
  }

  @Test
  public void deleteAccessControlEntry_whenNonExistentResource_throwsException() {
    try {
      subject.deleteAccessControlEntry( "Luke", new CredentialName("/some-thing-that-is-not-here"));
    } catch (EntryNotFoundException enfe) {
      assertThat(enfe.getMessage(), Matchers.equalTo("error.resource_not_found"));
    }
  }

  @Test
  public void deleteAccessControlEntry_whenNonExistentAce_doesNothing() {
    subject.deleteAccessControlEntry( "HelloKitty", credentialName);
  }

  @Test
  public void hasAclReadPermission_whenActorHasAclRead_returnsTrue() {
    assertThat(subject.hasReadAclPermission("HanSolo", CREDENTIAL_NAME),
        is(true));
  }

  @Test
  public void hasAclReadPermission_whenActorHasReadButNotReadAcl_returnsFalse() {
    assertThat(subject.hasReadAclPermission("Luke", CREDENTIAL_NAME),
        is(false));
  }

  @Test
  public void hasAclReadPermission_whenActorHasNoPermissions_returnsFalse() {
    assertThat(subject.hasReadAclPermission("Chewie", CREDENTIAL_NAME),
        is(false));
  }

  @Test
  public void hasAclReadPermission_whenCredentialDoesNotExist_returnsFalse() {
    assertThat(subject.hasReadAclPermission("Luke", CREDENTIAL_NAME_DOES_NOT_EXIST),
        is(false));
  }

  @Test
  public void hasAclWritePermission_whenActorHasAclWrite_returnsTrue() {
    assertThat(subject.hasAclWritePermission("HanSolo", CREDENTIAL_NAME),
        is(true));
  }

  @Test
  public void hasAclWritePermission_whenActorHasWriteButNotWriteAcl_returnsFalse() {
    assertThat(subject.hasAclWritePermission("Luke", CREDENTIAL_NAME),
        is(false));
  }

  @Test
  public void hasAclWritePermission_whenActorHasNoPermissions_returnsFalse() {
    assertThat(subject.hasAclWritePermission("Chewie", CREDENTIAL_NAME),
        is(false));
  }

  @Test
  public void hasAclWritePermission_whenCredentialDoesNotExist_returnsFalse() {
    assertThat(subject.hasAclWritePermission("Luke", CREDENTIAL_NAME_DOES_NOT_EXIST),
        is(false));
  }

  @Test
  public void hasReadPermission_whenActorHasRead_returnsTrue() {
    assertThat(subject.hasReadPermission("Leia", CREDENTIAL_NAME),
        is(true));
  }

  @Test
  public void hasReadPermission_givenNameWithoutLeadingSlashAndHasRead_returnsTrue() {
    assertThat(subject.hasReadPermission("Leia", CREDENTIAL_NAME),
        is(true));
  }

  @Test
  public void hasReadPermission_whenActorHasWriteButNotRead_returnsFalse() {
    assertThat(subject.hasReadPermission("Luke", CREDENTIAL_NAME),
        is(false));
  }

  @Test
  public void hasReadPermission_whenActorHasNoPermissions_returnsFalse() {
    assertThat(subject.hasReadPermission("Chewie", CREDENTIAL_NAME),
        is(false));
  }

  @Test
  public void hasCredentialWritePermission_whenActorHasWritePermission_returnsTrue() {
    assertThat(subject.hasCredentialWritePermission("Luke", CREDENTIAL_NAME), is(true));
  }

  @Test
  public void hasCredentialWritePermission_whenActorOnlyHasOtherPermissions_returnsFalse() {
    assertThat(subject.hasCredentialWritePermission("Leia", CREDENTIAL_NAME), is(false));
  }

  @Test
  public void hasCredentialWritePermission_whenActorHasNoPermissions_returnsFalse() {
    assertThat(subject.hasCredentialWritePermission("Darth", CREDENTIAL_NAME), is(false));
  }

  @Test
  public void hasCredentialDeletePermission_whenActorHasDeletePermission_returnsTrue() {
    assertThat(subject.hasCredentialDeletePermission("Luke", CREDENTIAL_NAME), is(true));
  }

  @Test
  public void hasCredentialDeletePermission_whenActorOnlyHasOtherPermissions_returnsFalse() {
    assertThat(subject.hasCredentialDeletePermission("Leia", CREDENTIAL_NAME), is(false));
  }

  @Test
  public void hasCredentialDeletePermission_whenActorHasNoPermissions_returnsFalse() {
    assertThat(subject.hasCredentialDeletePermission("Darth", CREDENTIAL_NAME), is(false));
  }

  @Test
  public void hasReadPermission_whenCredentialDoesNotExist_returnsFalse() {
    assertThat(subject.hasReadPermission("Luke", CREDENTIAL_NAME_DOES_NOT_EXIST),
        is(false));
  }

  private void seedDatabase() {
    final ValueCredentialData valueCredentialData = new ValueCredentialData(CREDENTIAL_NAME);
    credentialName = valueCredentialData.getCredentialName();

    credentialName = credentialNameDataService.save(credentialName);

    subject.saveAccessControlEntries(
        credentialName,
        singletonList(new AccessControlEntry("Luke",
            newArrayList(AccessControlOperation.WRITE, AccessControlOperation.DELETE)))
    );

    subject.saveAccessControlEntries(
        credentialName,
        singletonList(new AccessControlEntry("Leia",
            singletonList(AccessControlOperation.READ)))
    );

    subject.saveAccessControlEntries(
        credentialName,
        singletonList(new AccessControlEntry("HanSolo",
            newArrayList(AccessControlOperation.READ_ACL, AccessControlOperation.WRITE_ACL)))
    );
  }
}

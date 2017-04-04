package io.pivotal.security.data;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static java.util.Collections.singletonList;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.core.IsEqual.equalTo;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.AccessEntriesRequest;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.util.List;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AccessControlDataServiceTest {

  @Autowired
  private AccessControlDataService subject;

  @Autowired
  private SecretDataService secretDataService;

  private AccessEntriesRequest request;

  {
    wireAndUnwire(this);

    describe("#getAccessControlList", () -> {
      beforeEach(this::seedDatabase);

      describe("when given an existing credential name", () -> {
        it("returns the access control list", () -> {
          List<AccessControlEntry> accessControlEntries = subject.getAccessControlList("/lightsaber");

          assertThat(accessControlEntries, hasSize(2));

          AccessControlEntry accessControlEntry = accessControlEntries.get(0);

          assertThat(accessControlEntries, containsInAnyOrder(
              allOf(hasProperty("actor", equalTo("Luke")),
                  hasProperty("allowedOperations", hasItems(AccessControlOperation.WRITE))),
              allOf(hasProperty("actor", equalTo("Leia")),
                  hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))))
          );
        });
      });

      describe("when given a credential name that doesn't exist", () -> {
        itThrows("when credential does not exist", EntryNotFoundException.class, () -> {
          subject.getAccessControlList("/unicorn");
        });
      });
    });

    describe("#setAccessControlEntries", () -> {
      describe("when given an existing ACE for a resource", () -> {
        beforeEach(() -> {
          seedDatabase();

          List<AccessControlEntry> newAces = singletonList(
              new AccessControlEntry("Luke", singletonList(AccessControlOperation.READ)));

          request = new AccessEntriesRequest("/lightsaber", newAces);
        });

        it("returns the acl for the given resource", () -> {
          List<AccessControlEntry> response = subject.setAccessControlEntries(request);

          assertThat(response, containsInAnyOrder(
              allOf(hasProperty("actor", equalTo("Luke")),
                  hasProperty("allowedOperations",
                      hasItems(AccessControlOperation.READ, AccessControlOperation.WRITE))),
              allOf(hasProperty("actor", equalTo("Leia")),
                  hasProperty("allowedOperations", hasItems(AccessControlOperation.READ)))));
        });
      });

      describe("when given a new ACE for a resource", () -> {
        beforeEach(() -> {
          secretDataService.save(new NamedValueSecret("lightsaber2"));
          List<AccessControlEntry> newAces = singletonList(
              new AccessControlEntry("Luke", singletonList(AccessControlOperation.READ)));

          request = new AccessEntriesRequest("/lightsaber2", newAces);
        });

        it("returns the acl for the given resource", () -> {
          List<AccessControlEntry> response = subject.setAccessControlEntries(request);

          assertThat(response.size(), equalTo(1));
          assertThat(response.get(0).getActor(), equalTo("Luke"));
          assertThat(response.get(0).getAllowedOperations().size(),
              equalTo(1));
          assertThat(response.get(0).getAllowedOperations(),
              hasItem(AccessControlOperation.READ));
        });
      });
    });

    describe("deleteAccessControlEntry", () -> {
      beforeEach(this::seedDatabase);

      describe("when given a credential and actor that exists in the ACL", () -> {
        it("removes the ACE from the ACL", () -> {
          assertThat(subject.getAccessControlList("/lightsaber"),
              containsInAnyOrder(
                  allOf(hasProperty("actor", equalTo("Luke")),
                      hasProperty("allowedOperations", hasItems(AccessControlOperation.WRITE))),
                  allOf(hasProperty("actor", equalTo("Leia")),
                      hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))))
          );
          subject.deleteAccessControlEntries("/lightsaber", "Luke");

          final List<AccessControlEntry> accessControlList = subject
              .getAccessControlList("/lightsaber");
          assertThat(accessControlList,
              not(hasItem(hasProperty("actor", equalTo("Luke")))));
          assertThat(accessControlList, contains(
              allOf(hasProperty("actor", equalTo("Leia")),
                  hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))))
          );
        });
      });

      describe("when the credential/actor combination does not exist in the ACL", () -> {
        itThrows("when credential does not exist", EntryNotFoundException.class, () -> {
          subject.deleteAccessControlEntries("/some-thing-that-is-not-here", "Luke");
        });

        itThrows("when credential does exist, but the ACE does not", EntryNotFoundException.class,
            () -> {
              subject.deleteAccessControlEntries("/lightsaber", "HelloKitty");
            });
      });
    });

  }

  private void seedDatabase() {

    secretDataService.save(new NamedValueSecret("lightsaber"));

    subject.setAccessControlEntries(
        new AccessEntriesRequest(
            "lightsaber",
            singletonList(new AccessControlEntry("Luke",
                singletonList(AccessControlOperation.WRITE)))
        ));

    subject.setAccessControlEntries(
        new AccessEntriesRequest(
            "lightsaber",
            singletonList(new AccessControlEntry("Leia",
                singletonList(AccessControlOperation.READ)))
        ));
  }
}

package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessControlListResponse;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

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
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AccessControlDataServiceTest {

  @Autowired
  private AccessControlDataService subject;

  @Autowired
  private SecretDataService secretDataService;

  private AccessEntryRequest request;

  {
    wireAndUnwire(this);

    describe("setAccessControlEntry", () -> {
      describe("when given an existing ACE for a resource", () -> {
        beforeEach(() -> {

          seedDatabase();

          List<AccessControlEntry> newAces = singletonList(
            new AccessControlEntry("Luke", singletonList(AccessControlOperation.READ)));

          request = new AccessEntryRequest("/lightsaber", newAces);
        });

        it("returns the acl for the given resource", () -> {
          AccessControlListResponse response = subject.setAccessControlEntry(request);

          assertThat(response.getCredentialName(), equalTo("/lightsaber"));

          assertThat(response.getAccessControlList(), hasItems(
            allOf(hasProperty("actor", equalTo("Luke")),
              hasProperty("allowedOperations", hasItems(AccessControlOperation.READ, AccessControlOperation.WRITE)))
          ));
          assertThat(response.getAccessControlList(), hasItems(
            allOf(hasProperty("actor", equalTo("Leia")),
              hasProperty("allowedOperations", hasItems(AccessControlOperation.READ)))));
        });
      });

      describe("when given a new ACE for a resource", () -> {
        beforeEach(() -> {
          secretDataService.save(new NamedValueSecret("lightsaber2"));
          List<AccessControlEntry> newAces = singletonList(
            new AccessControlEntry("Luke", singletonList(AccessControlOperation.READ)));

          request = new AccessEntryRequest("/lightsaber2", newAces);
        });

        it("returns the acl for the given resource", () -> {
          AccessControlListResponse response = subject.setAccessControlEntry(request);

          assertThat(response.getCredentialName(), equalTo("/lightsaber2"));
          assertThat(response.getAccessControlList().size(), equalTo(1));
          assertThat(response.getAccessControlList().get(0).getActor(), equalTo("Luke"));
          assertThat(response.getAccessControlList().get(0).getAllowedOperations().size(), equalTo(1));
          assertThat(response.getAccessControlList().get(0).getAllowedOperations(), hasItem(AccessControlOperation.READ));
        });
      });
    });

    describe("getAccessControlListResponse", () -> {
      beforeEach(this::seedDatabase);

      describe("when given an existing credential name", () -> {
        it("returns the access control list", () -> {
          AccessControlListResponse response = subject.getAccessControlListResponse("/lightsaber");

          assertThat(response.getCredentialName(), equalTo("/lightsaber"));

          assertThat(response.getAccessControlList(), containsInAnyOrder(
            allOf(hasProperty("actor", equalTo("Luke")),
              hasProperty("allowedOperations", hasItems(AccessControlOperation.WRITE))),
            allOf(hasProperty("actor", equalTo("Leia")),
              hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))))
          );
        });
      });

      describe("when given a credential name that doesn't exist", () -> {
        itThrows("when credential does not exist", EntryNotFoundException.class, () -> {
          subject.getAccessControlListResponse("/unicorn");
        });
      });
    });

    describe("deleteAccessControlEntry", () -> {
      beforeEach(this::seedDatabase);

      describe("when given a credential and actor that exists in the ACL", () -> {
        it("removes the ACE from the ACL", () -> {
          assertThat(subject.getAccessControlListResponse("/lightsaber").getAccessControlList(), containsInAnyOrder(
              allOf(hasProperty("actor", equalTo("Luke")),
                  hasProperty("allowedOperations", hasItems(AccessControlOperation.WRITE))),
              allOf(hasProperty("actor", equalTo("Leia")),
                  hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))))
          );
          subject.deleteAccessControlEntry("/lightsaber", "Luke");


          final List<AccessControlEntry> accessControlList = subject.getAccessControlListResponse("/lightsaber").getAccessControlList();
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
            subject.deleteAccessControlEntry("/some-thing-that-is-not-here", "Luke");
        });

        itThrows("when credential does exist, but the ACE does not", EntryNotFoundException.class, () -> {
          subject.deleteAccessControlEntry("/lightsaber", "HelloKitty");
        });
      });
    });

  }

  private void seedDatabase() {

    secretDataService.save(new NamedValueSecret("lightsaber"));

    subject.setAccessControlEntry(
          new AccessEntryRequest(
              "lightsaber",
              singletonList(new AccessControlEntry("Luke",
                  singletonList(AccessControlOperation.WRITE)))
        ));

    subject.setAccessControlEntry(
        new AccessEntryRequest(
            "lightsaber",
            singletonList(new AccessControlEntry("Leia",
                singletonList(AccessControlOperation.READ)))
        ));
  }
}

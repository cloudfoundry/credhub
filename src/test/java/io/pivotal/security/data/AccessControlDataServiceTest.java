package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessControlListResponse;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.core.IsEqual.equalTo;

import java.util.Collections;
import java.util.List;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AccessControlDataServiceTest {

  @Autowired
  private AccessControlDataService subject;

  @Autowired
  private SecretNameRepository secretNameRepository;

  @Autowired
  private AccessEntryRepository accessEntryRepository;

  private AccessEntryRequest request;

  private SecretName secretName;

  {
    wireAndUnwire(this);

    describe("setAccessControlEntry", () -> {
      describe("when given an existing ACE for a resource", () -> {
        beforeEach(() -> {

          seedDatabase();

          List<AccessControlEntry> newAces = Collections.singletonList(
            new AccessControlEntry("Luke", Collections.singletonList(AccessControlOperation.READ)));

          request = new AccessEntryRequest("/lightsaber", newAces);
        });

        it("returns the acl for the given resource", () -> {
          AccessControlListResponse response = subject.setAccessControlEntry(request);

          assertThat(response.getCredentialName(), equalTo("/lightsaber"));

          assertThat(response.getAccessControlList(), hasItems(
            allOf(hasProperty("actor", equalTo("Luke")),
              hasProperty("operations", hasItems(AccessControlOperation.READ, AccessControlOperation.WRITE)))
          ));
          assertThat(response.getAccessControlList(), hasItems(
            allOf(hasProperty("actor", equalTo("Leia")),
              hasProperty("operations", hasItems(AccessControlOperation.READ)))));
        });
      });

      describe("when given a new ACE for a resource", () -> {
        beforeEach(() -> {
          secretName = secretNameRepository.saveAndFlush(new SecretName("lightsaber2"));

          List<AccessControlEntry> newAces = Collections.singletonList(
            new AccessControlEntry("Luke", Collections.singletonList(AccessControlOperation.READ)));

          request = new AccessEntryRequest("/lightsaber2", newAces);
        });

        it("returns the acl for the given resource", () -> {
          AccessControlListResponse response = subject.setAccessControlEntry(request);

          assertThat(response.getCredentialName(), equalTo("/lightsaber2"));
          assertThat(response.getAccessControlList().size(), equalTo(1));
          assertThat(response.getAccessControlList().get(0).getActor(), equalTo("Luke"));
          assertThat(response.getAccessControlList().get(0).getOperations().size(), equalTo(1));
          assertThat(response.getAccessControlList().get(0).getOperations(), hasItem(AccessControlOperation.READ));

          AccessEntryData data = accessEntryRepository.findAll().stream()
            .filter((entry) -> entry.getActor().equals("Luke")).findFirst().get();

          assertThat(data.getReadPermission(), equalTo(true));
          assertThat(data.getWritePermission(), equalTo(false));
          assertThat(data.getCredentialName().getUuid(), equalTo(secretName.getUuid()));
        });
      });
    });

    describe("getAccessControlList", () -> {
      beforeEach(this::seedDatabase);

      describe("when given an existing credential name", () -> {
        it("returns the access control list", () -> {
          AccessControlListResponse response = subject.getAccessControlList("/lightsaber");

          assertThat(response.getCredentialName(), equalTo("/lightsaber"));

          assertThat(response.getAccessControlList(), containsInAnyOrder(
            allOf(hasProperty("actor", equalTo("Luke")),
              hasProperty("operations", hasItems(AccessControlOperation.WRITE))),
            allOf(hasProperty("actor", equalTo("Leia")),
              hasProperty("operations", hasItems(AccessControlOperation.READ))))
          );
        });
      });

      describe("when given a credential name that doesn't exist", () -> {
        it("returns null", () -> {
          assertThat(subject.getAccessControlList("/unicorn"), nullValue());
        });
      });
    });

    describe("deleteAccessControlEntry", () -> {
      beforeEach(this::seedDatabase);

      describe("when given a credential and actor that exists in the ACL", () -> {
        it("removes the ACE from the ACL", () -> {
          assertThat(subject.getAccessControlList("/lightsaber").getAccessControlList(), containsInAnyOrder(
              allOf(hasProperty("actor", equalTo("Luke")),
                  hasProperty("operations", hasItems(AccessControlOperation.WRITE))),
              allOf(hasProperty("actor", equalTo("Leia")),
                  hasProperty("operations", hasItems(AccessControlOperation.READ))))
          );
          subject.deleteAccessControlEntry("/lightsaber", "Luke");

          final List<AccessControlEntry> accessControlList = subject.getAccessControlList("/lightsaber").getAccessControlList();
          assertThat(accessControlList,
              not(hasItem(hasProperty("actor", equalTo("Luke")))));
          assertThat(accessControlList, contains(
              allOf(hasProperty("actor", equalTo("Leia")),
                  hasProperty("operations", hasItems(AccessControlOperation.READ))))
          );
        });
      });
    });

  }

  private void seedDatabase() {
    SecretName secretName = secretNameRepository.saveAndFlush(new SecretName("lightsaber"));

    accessEntryRepository.saveAndFlush(new AccessEntryData(secretName,
      "Luke",
      false,
      true
    ));

    accessEntryRepository.saveAndFlush(new AccessEntryData(secretName,
      "Leia",
      true,
      false
    ));
  }
}

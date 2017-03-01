package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.SecretName;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessEntryResponse;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.core.IsEqual.equalTo;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Collections;
import java.util.List;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AccessControlServiceTest {

  @Autowired
  private AccessControlService subject;

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

          List<AccessControlEntry> newAces = Collections.singletonList(
              new AccessControlEntry("Luke", Collections.singletonList("read")));

          request = new AccessEntryRequest("/lightsaber", newAces);
        });

        it("returns the acl for the given resource", () -> {
          AccessEntryResponse response = subject.setAccessControlEntry(request);

          assertThat(response.getResource(), equalTo("/lightsaber"));

          assertThat(response.getAcls(), hasItems(
              allOf(hasProperty("actor", equalTo("Luke")),
                    hasProperty("operations", hasItems("read", "write")))
          ));
          assertThat(response.getAcls(), hasItems(
              allOf(hasProperty("actor", equalTo("Leia")),
                    hasProperty("operations", hasItems("read")))
          ));
        });
      });

      describe("when given a new ACE for a resource", () -> {
        beforeEach(() -> {
          secretName = secretNameRepository.saveAndFlush(new SecretName("lightsaber"));

          List<AccessControlEntry> newAces = Collections.singletonList(
              new AccessControlEntry("Luke", Collections.singletonList("read")));

          request = new AccessEntryRequest("/lightsaber", newAces);
        });

        it("returns the acl for the given resource", () -> {
          AccessEntryResponse response = subject.setAccessControlEntry(request);

          assertThat(response.getResource(), equalTo("/lightsaber"));
          assertThat(response.getAcls().size(), equalTo(1));
          assertThat(response.getAcls().get(0).getActor(), equalTo("Luke"));
          assertThat(response.getAcls().get(0).getOperations().size(), equalTo(1));
          assertThat(response.getAcls().get(0).getOperations(), hasItem("read"));

          AccessEntryData data = accessEntryRepository.findAll().stream()
              .filter((entry) -> entry.getActor().equals("Luke")).findFirst().get();

          assertThat(data.getReadPermission(), equalTo(true));
          assertThat(data.getWritePermission(), equalTo(false));
          assertThat(data.getResource().getUuid(), equalTo(secretName.getUuid()));
        });
      });
    });
  }
}

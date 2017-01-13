package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.exparity.hamcrest.BeanMatchers.theSameAs;
import static org.hamcrest.MatcherAssert.assertThat;

import java.time.Instant;
import java.util.List;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class FindResultsTest {
  private FindCredentialResults expectedResults;

  {
    describe("FindResultsTest", () -> {
      describe("#fromEntity", () -> {
        List<NamedSecret> namedSecretList = newArrayList();

        it("creates an object with a list of results containing credential names and updated times", () -> {
          Instant versionCreatedAt1 = Instant.ofEpochSecond(10000L, 0);
          Instant versionCreatedAt2 = Instant.ofEpochSecond(20000L, 0);
          Instant versionCreatedAt3 = Instant.ofEpochSecond(30000L, 0);
          namedSecretList.clear();
          String valueName = "valueSecret";
          String passwordName = "passwordSecret";
          String certificateName = "certificateSecret";
          namedSecretList.add(new NamedValueSecret(valueName).setVersionCreatedAt(versionCreatedAt2));
          namedSecretList.add(new NamedPasswordSecret(passwordName).setVersionCreatedAt(versionCreatedAt1));
          namedSecretList.add(new NamedCertificateSecret(certificateName).setVersionCreatedAt(versionCreatedAt3));

          expectedResults = new FindCredentialResults(newArrayList(
              new Credential(certificateName, versionCreatedAt3),
              new Credential(valueName, versionCreatedAt2),
              new Credential(passwordName, versionCreatedAt1)));

          FindCredentialResults results = FindCredentialResults.fromEntity(namedSecretList);
          assertThat(results, theSameAs(expectedResults));
        });
      });
    });
  }
}

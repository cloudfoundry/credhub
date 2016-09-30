package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.uniquify;
import static org.exparity.hamcrest.BeanMatchers.theSameAs;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class FindResultsTest {
  private FindCredentialResults expectedResults;

  {
    describe("FindResultsTest", () -> {
      describe("#fromEntity", () -> {
        List<NamedSecret> namedSecretList = newArrayList();

        it("creates an object with a list of results containing credential names and updated times", () -> {
          Instant updatedAt1 = Instant.ofEpochSecond(10000L, 0);
          Instant updatedAt2 = Instant.ofEpochSecond(20000L, 0);
          Instant updatedAt3 = Instant.ofEpochSecond(30000L, 0);
          namedSecretList.clear();
          String valueName = uniquify("valueSecret");
          String passwordName = uniquify("passwordSecret");
          String certificateName = uniquify("certificateSecret");
          namedSecretList.add(new NamedValueSecret(valueName).setUpdatedAt(updatedAt2));
          namedSecretList.add(new NamedPasswordSecret(passwordName).setUpdatedAt(updatedAt1));
          namedSecretList.add(new NamedCertificateSecret(certificateName).setUpdatedAt(updatedAt3));

          expectedResults = new FindCredentialResults(newArrayList(
              new Credential(certificateName, updatedAt3),
              new Credential(valueName, updatedAt2),
              new Credential(passwordName, updatedAt1)));

          FindCredentialResults results = FindCredentialResults.fromEntity(namedSecretList);
          assertThat(results, theSameAs(expectedResults));
        });
      });
    });
  }
}

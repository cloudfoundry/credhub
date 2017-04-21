package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class FindCredentialResultsTest {

  {
    describe("#fromCredentials", () -> {
      it("wraps the credentials as credentials", () -> {
        Instant versionCreatedAt1 = Instant.ofEpochSecond(10000L, 0);
        Instant versionCreatedAt2 = Instant.ofEpochSecond(20000L, 0);
        Instant versionCreatedAt3 = Instant.ofEpochSecond(30000L, 0);

        String valueName = "valueSecret";
        String passwordName = "passwordSecret";
        String certificateName = "certificateSecret";

        List<CredentialView> credentialViews = newArrayList(
            new CredentialView(versionCreatedAt3, certificateName),
            new CredentialView(versionCreatedAt2, valueName),
            new CredentialView(versionCreatedAt1, passwordName)
        );

        assertThat(new FindCredentialResults(credentialViews).getCredentials(), equalTo(credentialViews));
      });
    });
  }
}

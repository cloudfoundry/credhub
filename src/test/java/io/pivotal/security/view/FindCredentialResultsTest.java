package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import java.time.Instant;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
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

        List<FindCredentialResult> credentialViews = newArrayList(
            new FindCredentialResult(versionCreatedAt3, certificateName),
            new FindCredentialResult(versionCreatedAt2, valueName),
            new FindCredentialResult(versionCreatedAt1, passwordName)
        );

        assertThat(new FindCredentialResults(credentialViews).getCredentials(), equalTo(credentialViews));
      });
    });
  }
}

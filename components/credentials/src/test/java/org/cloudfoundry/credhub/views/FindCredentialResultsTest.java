package org.cloudfoundry.credhub.views;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import static com.google.common.collect.Lists.newArrayList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class FindCredentialResultsTest {

  @Test
  public void fromCredentials_wrapsTheCredentialsAsCredentialViews() {
    final Instant versionCreatedAt1 = Instant.ofEpochSecond(10000L, 0);
    final Instant versionCreatedAt2 = Instant.ofEpochSecond(20000L, 0);
    final Instant versionCreatedAt3 = Instant.ofEpochSecond(30000L, 0);

    final String valueName = "valueSecret";
    final String passwordName = "passwordSecret";
    final String certificateName = "certificateSecret";

    final List<FindCredentialResult> credentialViews = newArrayList(
      new FindCredentialResult(versionCreatedAt3, certificateName),
      new FindCredentialResult(versionCreatedAt2, valueName),
      new FindCredentialResult(versionCreatedAt1, passwordName)
    );

    assertThat(new FindCredentialResults(credentialViews).getCredentials(), equalTo(credentialViews));
  }
}


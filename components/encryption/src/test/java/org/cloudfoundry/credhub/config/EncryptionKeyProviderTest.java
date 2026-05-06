package org.cloudfoundry.credhub.config;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

public class EncryptionKeyProviderTest {

  @Test
  public void initializesWithAnEmptyButAppendableKeyList() {
    final EncryptionKeyProvider provider = new EncryptionKeyProvider();
    assertThat(provider.getKeys(), is(empty()));
    provider.getKeys().add(new EncryptionKeyMetadata());
    assertThat(provider.getKeys(), hasSize(1));
  }
}

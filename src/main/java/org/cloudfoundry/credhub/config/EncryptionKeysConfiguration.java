package org.cloudfoundry.credhub.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("encryption")
public class EncryptionKeysConfiguration {

  private List<EncryptionKeyProvider> providers;
  private boolean keyCreationEnabled;

  public List<EncryptionKeyProvider> getProviders() {
    return providers;
  }

  public void setProviders(final List<EncryptionKeyProvider> providers) {
    this.providers = providers;
  }

  public boolean isKeyCreationEnabled() {
    return keyCreationEnabled;
  }

  public void setKeyCreationEnabled(final boolean keyCreationEnabled) {
    this.keyCreationEnabled = keyCreationEnabled;
  }


}

package org.cloudfoundry.credhub.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties("encryption")
public class EncryptionKeysConfiguration {

  private List<EncryptionKeyMetadata> keys;
  private ProviderType provider;

  public List<EncryptionKeyMetadata> getKeys() {
    return keys;
  }

  public void setKeys(List<EncryptionKeyMetadata> keys) {
    this.keys = keys;
  }

  public ProviderType getProvider() {
    return provider;
  }

  public void setProvider(ProviderType provider) {
    this.provider = provider;
  }
}

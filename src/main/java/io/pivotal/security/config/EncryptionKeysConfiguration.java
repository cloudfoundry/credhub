package io.pivotal.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
@ConfigurationProperties("encryption")
public class EncryptionKeysConfiguration {
  private final List<EncryptionKeyMetadata> keys;

  public EncryptionKeysConfiguration() {
    this(new ArrayList<>());
  }

  public EncryptionKeysConfiguration(List<EncryptionKeyMetadata> keys) {
    this.keys = keys;
  }

  public List<EncryptionKeyMetadata> getKeys() { return keys; }
}

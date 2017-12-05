package org.cloudfoundry.credhub.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

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

  public List<EncryptionKeyMetadata> getKeys() {
    return keys;
  }
}

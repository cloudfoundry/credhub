package io.pivotal.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
@ConfigurationProperties("encryption")
public class EncryptionKeysConfiguration {
  private List<String> keys = new ArrayList<>();

  public List<String> getKeys() { return keys; }
}

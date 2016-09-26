package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dev_internal")
public class DevKeyProvider {
  @Value("${encryption.dev-key}")
  private String devKey;

  public String getDevKey() {
    return devKey;
  }
}
package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class DevKeyProvider {
  @Value("${encryption.dev-key}")
  private String devKey;

  public String getDevKey() {
    return devKey;
  }
}